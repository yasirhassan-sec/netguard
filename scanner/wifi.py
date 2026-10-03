"""Wi-Fi survey: nearby networks, signal strength, and the current connection."""
import re
import threading
import time
from collections import Counter, deque

from .utils import IS_LINUX, IS_WINDOWS, run_cmd
from .vulns import wifi_risk

# Signal samples of the current connection: (unix time, percent, dBm). ~10 minutes at 15 s.
_history = deque(maxlen=40)
_sampler_started = False

# "Key      : value" lines from netsh. Values (MACs) can contain colons, so split on
# the first colon that has whitespace before it.
_KV = re.compile(r"^\s*(.+?)\s+:\s?(.*)$")


def signal_quality(pct):
    if pct >= 80:
        return "Excellent"
    if pct >= 60:
        return "Good"
    if pct >= 40:
        return "Fair"
    return "Weak"


def pct_to_dbm(pct):
    # Windows' signal quality is a linear map of roughly -100 dBm (0%) to -50 dBm (100%).
    return round(pct / 2 - 100)


def band_from_channel(channel):
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return ""
    if ch <= 14:
        return "2.4 GHz"
    if ch <= 177:
        return "5 GHz"
    return "6 GHz"


def _int(text):
    digits = re.sub(r"[^\d-]", "", text or "")
    try:
        return int(digits)
    except ValueError:
        return None


# ---------------------------------------------------------------- Windows ---

def _windows_networks():
    out, _ = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"])
    rows, net, bss = [], None, None
    for line in out.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        if re.fullmatch(r"SSID \d+", key):
            net = {"ssid": val or "(hidden network)", "auth": "", "encryption": ""}
            bss = None
        elif net is None:
            continue
        elif re.fullmatch(r"BSSID \d+", key):
            bss = dict(net, bssid=val.lower(), signal=0, radio="", band="", channel="")
            rows.append(bss)
        elif key == "Authentication":
            net["auth"] = val
        elif key == "Encryption":
            net["encryption"] = val
        elif bss is not None:
            if key == "Signal":
                bss["signal"] = _int(val) or 0
            elif key == "Radio type":
                bss["radio"] = val
            elif key == "Band":
                bss["band"] = val
            elif key == "Channel":
                bss["channel"] = val
    return rows, out


def _windows_connection():
    out, _ = run_cmd(["netsh", "wlan", "show", "interfaces"])
    blocks, cur = [], None
    for line in out.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        if key == "Name":
            cur = {}
            blocks.append(cur)
        if cur is not None:
            cur[key] = val
    for b in blocks:
        if b.get("State", "").lower() != "connected":
            continue
        signal = _int(b.get("Signal")) or 0
        rssi = _int(b.get("Rssi"))
        return {
            "interface": b.get("Name", ""),
            "adapter": b.get("Description", ""),
            "ssid": b.get("SSID", ""),
            "bssid": (b.get("AP BSSID") or b.get("BSSID") or "").lower(),
            "auth": b.get("Authentication", ""),
            "encryption": b.get("Cipher", ""),
            "radio": b.get("Radio type", ""),
            "band": b.get("Band") or band_from_channel(b.get("Channel")),
            "channel": b.get("Channel", ""),
            "signal": signal,
            "dbm": rssi if rssi is not None else pct_to_dbm(signal),
            "quality": signal_quality(signal),
            "rx_mbps": b.get("Receive rate (Mbps)", ""),
            "tx_mbps": b.get("Transmit rate (Mbps)", ""),
        }
    return None


# ------------------------------------------------------------------ Linux ---

def _linux_networks():
    out, rc = run_cmd(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY",
                       "dev", "wifi", "list"])
    rows, connected = [], None
    for line in out.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 7:
            continue
        in_use, ssid, bssid, signal, chan, freq, security = parts[:7]
        sig = _int(signal) or 0
        row = {
            "ssid": ssid or "(hidden network)",
            "bssid": bssid.lower(),
            "auth": security or "Open",
            "encryption": "",
            "signal": sig,
            "radio": "",
            "band": band_from_channel(chan),
            "channel": chan,
        }
        rows.append(row)
        if in_use.strip() == "*":
            connected = dict(row, interface="", adapter="", dbm=pct_to_dbm(sig),
                             quality=signal_quality(sig), rx_mbps="", tx_mbps="")
    return rows, connected, rc


# ----------------------------------------------------------------- public ---

def survey():
    """Return the current connection and visible networks, one row per access point."""
    result = {"supported": True, "connected": None, "networks": [], "channels": [], "hint": ""}

    if IS_WINDOWS:
        rows, raw = _windows_networks()
        result["connected"] = _windows_connection()
        if not rows:
            if "location" in raw.lower():
                result["hint"] = ("Windows blocked the Wi-Fi scan: turn on Location services "
                                  "(Settings > Privacy & security > Location) and allow desktop apps.")
            elif "powered down" in raw.lower() or "no wireless interface" in raw.lower():
                result["hint"] = "No active Wi-Fi adapter found (it may be off or this PC uses Ethernet)."
            else:
                result["hint"] = "No networks visible yet. Windows refreshes this list every minute or so."
        elif len(rows) == 1:
            result["hint"] = ("Only one network visible. Windows lists networks from its last background scan; "
                              "open the Wi-Fi flyout in the taskbar to force a rescan, then click Refresh.")
    elif IS_LINUX:
        rows, connected, rc = _linux_networks()
        result["connected"] = connected
        if rc != 0:
            result["hint"] = "Wi-Fi survey needs NetworkManager (nmcli)."
    else:
        rows = []
        result["supported"] = False
        result["hint"] = "Wi-Fi survey is supported on Windows and Linux."

    conn = result["connected"]
    if conn:
        conn["risk"] = wifi_risk(conn["auth"], conn["encryption"])
    for r in rows:
        r["band"] = r["band"] or band_from_channel(r["channel"])
        r["dbm"] = pct_to_dbm(r["signal"])
        r["quality"] = signal_quality(r["signal"])
        r["connected"] = bool(conn and r["bssid"] == conn["bssid"])
        r["risk"] = wifi_risk(r["auth"], r["encryption"])
    rows.sort(key=lambda r: (not r["connected"], -r["signal"]))
    result["networks"] = rows
    result["history"] = list(_history)

    usage = Counter((r["band"], r["channel"]) for r in rows if r["channel"])
    result["channels"] = [{"band": b, "channel": c, "count": n}
                          for (b, c), n in sorted(usage.items(), key=lambda kv: (kv[0][0], _int(kv[0][1]) or 0))]
    return result


def _current_connection():
    if IS_WINDOWS:
        return _windows_connection()
    if IS_LINUX:
        return _linux_networks()[1]
    return None


def start_sampler(interval=15, enabled=lambda: True):
    """Background thread that records the connected network's signal for the trend chart."""
    global _sampler_started
    if _sampler_started:
        return
    _sampler_started = True

    def loop():
        while True:
            if enabled():
                conn = _current_connection()
                if conn:
                    _history.append({"t": int(time.time()), "signal": conn["signal"], "dbm": conn["dbm"],
                                     "ssid": conn["ssid"]})
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="wifi-sampler").start()
