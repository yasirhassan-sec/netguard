"""Vulnerability engine: detect -> explain -> recommend. Nothing here exploits anything.

Each finding carries evidence and a confidence level. The risk score is NetGuard's own
heuristic (severity x confidence), not an industry-standard metric such as CVSS.
"""
import json
import re
import time
import urllib.parse
import urllib.request

from . import oui

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_PENALTY = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}
CONFIDENCE_FACTOR = {"confirmed": 1.0, "likely": 0.8, "possible": 0.5}

CATEGORIES = ["Exposed Service", "Outdated Software", "Weak Configuration", "Encryption",
              "Wi-Fi", "Known CVE", "Inventory"]

# port: (rule id, severity, category, title, why it matters, how to fix)
PORT_RULES = {
    23: ("NG-TELNET", "high", "Exposed Service", "Telnet is enabled",
         "Telnet sends usernames and passwords in clear text and is the #1 way IoT botnets like Mirai break in.",
         "Disable Telnet in the device settings; use SSH or the vendor app instead."),
    21: ("NG-FTP", "medium", "Encryption", "FTP server is running",
         "FTP sends credentials and files unencrypted, so anyone on the network can capture them.",
         "Turn off FTP or switch to SFTP/FTPS."),
    445: ("NG-SMB", "medium", "Exposed Service", "SMB file sharing is exposed",
          "SMB has a long history of wormable bugs (EternalBlue/WannaCry). Exposed shares can leak files.",
          "Disable sharing if unused; make sure SMBv1 is off and the OS is fully patched."),
    139: ("NG-NETBIOS", "low", "Exposed Service", "NetBIOS is exposed",
          "Legacy NetBIOS leaks the machine name and shares and is rarely needed today.",
          "Disable NetBIOS over TCP/IP in the adapter's IPv4 > Advanced > WINS settings."),
    3389: ("NG-RDP", "medium", "Exposed Service", "Remote Desktop (RDP) is open",
           "RDP is a top target for password guessing and has had critical pre-auth bugs (BlueKeep).",
           "Disable Remote Desktop if unused, or require Network Level Authentication and a strong password."),
    5900: ("NG-VNC", "high", "Exposed Service", "VNC remote control is open",
           "VNC often has weak or no passwords and gives full control of the screen.",
           "Disable VNC or protect it with a strong password and only allow it over a VPN."),
    5555: ("NG-ADB", "critical", "Exposed Service", "Android Debug Bridge (ADB) is open",
           "Network ADB gives anyone on the network shell access to the device without a password.",
           "Turn off 'ADB debugging' / 'Network debugging' in Developer options."),
    2375: ("NG-DOCKER", "critical", "Exposed Service", "Docker API exposed without TLS",
           "The unauthenticated Docker API lets anyone run containers as root on the host.",
           "Bind Docker to the local socket only, or enable TLS on port 2376."),
    6379: ("NG-REDIS", "high", "Exposed Service", "Redis database is exposed",
           "Redis has no authentication by default and can be abused to write files or run code.",
           "Bind Redis to 127.0.0.1 and set 'requirepass'."),
    27017: ("NG-MONGO", "high", "Exposed Service", "MongoDB is exposed",
            "Unsecured MongoDB instances are routinely wiped and ransomed.",
            "Bind to 127.0.0.1 and enable authentication."),
    3306: ("NG-MYSQL", "medium", "Exposed Service", "MySQL is reachable on the network",
           "Database servers should not be reachable by every device on the LAN.",
           "Bind to 127.0.0.1 unless remote access is needed; use strong passwords."),
    5432: ("NG-PGSQL", "medium", "Exposed Service", "PostgreSQL is reachable on the network",
           "Database servers should not be reachable by every device on the LAN.",
           "Restrict listen_addresses and pg_hba.conf to trusted hosts."),
    1433: ("NG-MSSQL", "medium", "Exposed Service", "MSSQL is reachable on the network",
           "Database servers should not be reachable by every device on the LAN.",
           "Restrict access with the firewall; disable the 'sa' account."),
    11211: ("NG-MEMCACHED", "high", "Exposed Service", "Memcached is exposed",
            "Memcached has no authentication and leaks cached data.", "Bind to 127.0.0.1."),
    9200: ("NG-ELASTIC", "medium", "Exposed Service", "Elasticsearch is exposed",
           "Elasticsearch without security enabled lets anyone read and delete indexes.",
           "Enable xpack security or bind to localhost."),
    1883: ("NG-MQTT", "medium", "Encryption", "MQTT broker without TLS",
           "Smart-home MQTT brokers often allow anonymous clients to read and control devices.",
           "Disable anonymous access and use TLS on port 8883."),
    2049: ("NG-NFS", "medium", "Exposed Service", "NFS share is exposed",
           "NFS exports are often readable by any host on the LAN.", "Restrict exports to specific client IPs."),
    873: ("NG-RSYNC", "medium", "Exposed Service", "rsync daemon is exposed",
          "rsync modules without auth can leak or allow overwriting files.", "Require 'auth users' or disable the daemon."),
    111: ("NG-RPCBIND", "low", "Exposed Service", "RPCbind is exposed",
          "RPCbind reveals running RPC services and can be abused for amplification.", "Disable it if NFS is not used."),
    1080: ("NG-SOCKS", "medium", "Exposed Service", "SOCKS proxy is open",
           "An open proxy lets others relay traffic through your network.", "Disable the proxy or require authentication."),
    7547: ("NG-TR069", "low", "Exposed Service", "TR-069 management port is open",
           "TR-069 lets the ISP manage the router; flaws in it have been mass-exploited.",
           "Keep router firmware updated; ask your ISP if it can be disabled."),
    554: ("NG-RTSP", "low", "Exposed Service", "RTSP video stream is exposed",
          "Camera streams are often viewable with default or no credentials.",
          "Set a strong camera password and update its firmware."),
}

SECURITY_HEADERS = {
    "x-frame-options": "clickjacking protection",
    "x-content-type-options": "MIME sniffing protection",
    "content-security-policy": "script injection protection",
}


def _f(rule, severity, category, device, title, detail, fix, port=None, evidence="",
       confidence="confirmed", refs=None):
    if isinstance(device, dict):
        ip = device["ip"]
        host = f"{ip} ({device['hostname']})" if device.get("hostname") else ip
    else:
        ip, host = None, device
    entry = next((e for e in (device.get("open_ports", []) if isinstance(device, dict) else [])
                  if e["port"] == port), None)
    return {
        "id": f"{rule}-{ip or 'wifi'}-{port or 0}",
        "rule": rule, "severity": severity, "category": category, "confidence": confidence,
        "ip": ip, "host": host, "port": port,
        "service": entry["service"] if entry else "", "version": entry["version"] if entry else "",
        "title": title, "detail": detail, "evidence": evidence, "fix": fix, "refs": refs or [],
    }


def _version_tuple(text):
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


# ------------------------------------------------------------------- Wi-Fi ---

def wifi_risk(auth, enc):
    """Risk rating for any Wi-Fi network from its auth/cipher."""
    a, e = (auth or "").lower(), (enc or "").lower()
    if "open" in a or a in ("", "none"):
        return {"level": "high", "label": "Open", "advice": "Enable WPA2/WPA3 encryption"}
    if "wep" in a or "wep" in e:
        return {"level": "high", "label": "WEP (broken)", "advice": "Replace WEP with WPA2/WPA3"}
    if "tkip" in e or "wpa1" in a or a.startswith("wpa-") or a == "wpa":
        return {"level": "medium", "label": "WPA (weak)", "advice": "Upgrade to WPA2-AES or WPA3"}
    if "wpa3" in a or "sae" in a or "owe" in a:
        return {"level": "secure", "label": "WPA3", "advice": "Strong security"}
    if "wpa2" in a:
        return {"level": "low", "label": "WPA2", "advice": "Use a 12+ character passphrase; consider WPA3"}
    return {"level": "low", "label": auth or "Unknown", "advice": "Check router security settings"}


def check_wifi(wifi):
    findings = []
    conn = wifi.get("connected")
    if not conn:
        return findings
    host = f"Wi-Fi: {conn['ssid']}"
    risk = wifi_risk(conn["auth"], conn["encryption"])
    evidence = f"Authentication: {conn['auth']}, cipher: {conn['encryption']}"

    if risk["label"] == "Open":
        findings.append(_f("NG-WIFI-OPEN", "critical", "Wi-Fi", host, "Wi-Fi network has no password",
            "Anyone in range can join, see your devices and sniff unencrypted traffic.",
            "Enable WPA2-Personal (AES) or WPA3 in the router's wireless settings.", evidence=evidence))
    elif risk["label"].startswith("WEP"):
        findings.append(_f("NG-WIFI-WEP", "critical", "Wi-Fi", host, "Wi-Fi uses broken WEP encryption",
            "WEP can be cracked in minutes with free tools.",
            "Switch to WPA2-Personal (AES) or WPA3; replace the router if it can't.", evidence=evidence))
    elif risk["label"].startswith("WPA (weak)"):
        findings.append(_f("NG-WIFI-WPA1", "high", "Wi-Fi", host, "Wi-Fi uses outdated WPA/TKIP",
            "WPA1 and TKIP are deprecated and vulnerable to packet injection attacks.",
            "Use WPA2 with AES (CCMP) only, or WPA3.", evidence=evidence))
    elif risk["label"] == "WPA2":
        findings.append(_f("NG-WIFI-WPA2", "low", "Wi-Fi", host, "WPA2 instead of WPA3",
            "WPA2-Personal is secure with a long password, but its handshake can be captured and "
            "brute-forced offline. WPA3 (SAE) prevents that.",
            "Enable WPA3 or 'WPA2/WPA3 mixed' mode if all your devices support it; use a 12+ character passphrase.",
            evidence=evidence))

    if conn["signal"] < 40:
        findings.append(_f("NG-WIFI-SIGNAL", "info", "Wi-Fi", host,
            f"Weak Wi-Fi signal ({conn['signal']}%, {conn['dbm']} dBm)",
            "A weak signal lowers speed and makes connections drop.",
            "Move closer to the router, reposition it, or add a mesh node / access point.",
            evidence=f"Signal {conn['signal']}% / {conn['dbm']} dBm"))

    same = [n for n in wifi.get("networks", [])
            if n["channel"] == conn["channel"] and n["band"] == conn["band"] and not n["connected"]]
    if conn["band"].startswith("2.4") and len(same) >= 3:
        findings.append(_f("NG-WIFI-CHANNEL", "info", "Wi-Fi", host,
            f"Busy channel ({len(same)} other networks on channel {conn['channel']})",
            "Overlapping networks on the same 2.4 GHz channel cause interference and slowdowns.",
            "Set the router to channel 1, 6 or 11 (whichever is least used) or prefer 5 GHz.",
            evidence=", ".join(n["ssid"] for n in same[:6])))
    return findings


# ----------------------------------------------------------------- devices ---

def _service_checks(d, e):
    findings = []
    port, banner = e["port"], e["banner"]
    low = banner.lower()

    if "vsftpd 2.3.4" in low:
        findings.append(_f("NG-VSFTPD-BACKDOOR", "critical", "Outdated Software", d, "Backdoored vsftpd 2.3.4",
            "This exact FTP server version shipped with a backdoor that gives a root shell.",
            "Upgrade vsftpd immediately.", port, banner, refs=["CVE-2011-2523"]))

    m = re.search(r"openssh[_-](\d+\.\d+)(p\d+)?", low)
    if m:
        ver = _version_tuple(m.group(1))
        if (8, 5) <= ver <= (9, 7):
            findings.append(_f("NG-OPENSSH-REGRESSHION", "high", "Outdated Software", d,
                f"OpenSSH {m.group(1)} may be vulnerable to regreSSHion",
                "OpenSSH 8.5p1-9.7p1 on glibc Linux has a race condition allowing unauthenticated remote code "
                "execution. Distros backported fixes without changing the version, hence 'likely'.",
                "Update OpenSSH to 9.8p1 or later (or your distro's patched package).",
                port, banner, "likely", ["CVE-2024-6387"]))
        elif ver < (8, 5):
            findings.append(_f("NG-OPENSSH-OLD", "medium", "Outdated Software", d, f"Outdated OpenSSH {m.group(1)}",
                "Old OpenSSH releases have multiple known vulnerabilities.",
                "Update the device's firmware / OS packages.", port, banner, "likely"))

    if re.search(r"server:\s*boa/", low):
        findings.append(_f("NG-BOA", "high", "Outdated Software", d, "Abandoned Boa web server",
            "Boa was discontinued in 2005 and is common in cheap cameras/routers with unpatched flaws.",
            "Update the device firmware or isolate it on a guest/IoT network.", port, banner))

    if port == 6379 and "+pong" in low:
        findings.append(_f("NG-REDIS-NOAUTH", "critical", "Weak Configuration", d,
            "Redis accepts commands without a password",
            "Anyone on the network can read/write data and potentially execute code.",
            "Set 'requirepass' and bind Redis to 127.0.0.1.", port, "PING -> +PONG"))

    http = e.get("http")
    if http:
        if not http["tls"] and http["login_form"]:
            findings.append(_f("NG-HTTP-LOGIN", "medium", "Encryption", d,
                f"Login page served over plain HTTP (port {port})",
                "Passwords typed into this page are sent unencrypted across the network.",
                "Use the HTTPS admin page if available and change the default admin password.",
                port, http["banner"]))
        missing = [h for h in SECURITY_HEADERS if h not in http["headers"]]
        if http["tls"] and "strict-transport-security" not in http["headers"]:
            missing.append("strict-transport-security")
        # CSP alone is rarely set by embedded devices, so only flag when a basic header is missing too.
        if set(missing) - {"content-security-policy"} and (http["status"] or 0) < 400:
            findings.append(_f("NG-HTTP-HEADERS", "low", "Weak Configuration", d,
                f"Missing HTTP security headers (port {port})",
                "Without these headers the web interface is easier to attack with clickjacking or "
                "cross-site scripting from a malicious page you visit.",
                "Update the firmware; vendors add these headers in newer releases.",
                port, "Missing: " + ", ".join(missing), "confirmed"))
    return findings


def check_devices(devices, extra):
    """extra: {ip: {"smb1": bool, "tls_legacy": {port: ver}, "ftp_anon": bool}}"""
    findings = []
    vendor_db = oui.db_status()["installed"]
    for d in devices:
        x = extra.get(d["ip"], {})
        for e in d["open_ports"]:
            rule = PORT_RULES.get(e["port"])
            if rule:
                rid, sev, cat, title, detail, fix = rule
                title = f"{title} (port {e['port']})"
                evidence = e["banner"] or f"TCP {e['port']} accepted a connection"
                confidence = "confirmed"
                if d["is_self"]:
                    fw = d.get("firewall")
                    if fw is None:
                        confidence = "possible"
                        detail += (" (Seen from this PC itself, which bypasses its own firewall; "
                                   "check whether other devices can reach it too.)")
                    elif e["port"] in fw["allowed"]:
                        a = fw["allowed"][e["port"]]
                        evidence += (f" · Windows Firewall allows it on the {'/'.join(fw['profiles'])} "
                                     f"profile via rule '{a['rule']}' (from {a['remote'] or 'Any'})")
                    else:
                        sev = "info"
                        title = f"{e['service']} listens on port {e['port']} but the firewall blocks it"
                        detail = ("The service listens on this PC, but Windows Firewall blocks inbound "
                                  "connections to it on the active network profile, so other devices can't reach it.")
                        fix = "No action needed unless you change firewall rules. Stop the service if you don't use it."
                        evidence += f" · no inbound allow rule on the {'/'.join(fw['profiles'])} profile"
                findings.append(_f(rid, sev, cat, d, title, detail, fix, e["port"], evidence, confidence))
            findings += _service_checks(d, e)

        if x.get("smb1"):
            findings.append(_f("NG-SMB1", "critical", "Weak Configuration", d, "SMBv1 is enabled",
                "SMBv1 is the protocol abused by WannaCry and NotPetya (EternalBlue).",
                "Disable SMBv1 (Windows: 'Turn Windows features on or off' > uncheck SMB 1.0/CIFS).",
                445, "Server accepted an SMB1 'NT LM 0.12' negotiate request", refs=["CVE-2017-0144"]))
        for port, ver in (x.get("tls_legacy") or {}).items():
            findings.append(_f("NG-TLS-LEGACY", "medium", "Encryption", d, f"Deprecated {ver} accepted (port {port})",
                "TLS 1.0/1.1 are deprecated (RFC 8996) and weaken HTTPS protection.",
                "Update firmware so only TLS 1.2+ is offered.", port, f"Handshake completed using {ver}"))
        if x.get("ftp_anon"):
            findings.append(_f("NG-FTP-ANON", "high", "Weak Configuration", d, "Anonymous FTP login allowed",
                "Anyone on the network can log in to the FTP server without a password.",
                "Disable anonymous access in the FTP server settings.", 21, "USER anonymous -> 230 Login successful"))
        if d["snmp"]:
            findings.append(_f("NG-SNMP-PUBLIC", "high", "Weak Configuration", d,
                "SNMP answers to default community 'public'",
                "The device reveals its configuration to anyone on the network.",
                "Disable SNMP or change the community string; prefer SNMPv3.", 161, f"sysDescr: {d['snmp']}"))

        if d["is_gateway"]:
            if d["upnp"]:
                findings.append(_f("NG-UPNP", "medium", "Weak Configuration", d, "UPnP is enabled on the router",
                    "Any program or infected device on your LAN can silently open ports to the internet.",
                    "Disable UPnP in the router unless a game console/app really needs it.",
                    1900, "SSDP: " + (d["upnp"][0]["server"] or d["upnp"][0]["st"])))
            web = {e["port"] for e in d["open_ports"]}
            if web & {80, 8080} and not web & {443, 8443}:
                findings.append(_f("NG-ROUTER-HTTP", "low", "Encryption", d, "Router admin is HTTP-only",
                    "The router's web interface doesn't offer HTTPS, so the admin password travels in clear text.",
                    "Only manage the router over a wired connection, and change the default admin password.",
                    80, "No HTTPS port open on the gateway"))

        if (vendor_db and not d["is_self"] and not d["is_gateway"]
                and d["vendor"] == "Unknown" and not d["hostname"]):
            findings.append(_f("NG-UNKNOWN-DEVICE", "info", "Inventory", d, "Unidentified device on the network",
                "No hostname or known manufacturer. It may be fine, but verify you recognise it.",
                "Check the router's client list; if unknown, change the Wi-Fi password.",
                evidence=f"MAC {d['mac']}", confidence="possible"))
    return findings


# --------------------------------------------------------------------- NVD ---

_nvd_cache = {}


def cve_lookup(devices, log=None, limit=8):
    """Query the NVD for CVEs matching detected product/version strings (opt-in, online)."""
    products = {}
    for d in devices:
        for e in d["open_ports"]:
            if e["version"] and re.search(r"\d+\.\d+", e["version"]):
                products.setdefault(e["version"], []).append((d, e))
    findings = []
    for key, hits in list(products.items())[:limit]:
        if key not in _nvd_cache:
            if log:
                log(f"NVD lookup: {key}")
            url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&keywordSearch="
                   + urllib.parse.quote(key))
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetGuard"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = json.load(resp)
                _nvd_cache[key] = [(v["cve"]["id"], _cvss(v["cve"]), _desc(v["cve"]))
                                   for v in data.get("vulnerabilities", [])]
            except Exception as exc:  # network errors shouldn't abort the scan
                if log:
                    log(f"NVD lookup failed for {key}: {exc}")
                _nvd_cache[key] = []
            time.sleep(6.5)  # NVD allows 5 requests / 30 s without an API key
        cves = _nvd_cache[key]
        if not cves:
            continue
        top = max(c[1] for c in cves)
        sev = "critical" if top >= 9 else "high" if top >= 7 else "medium" if top >= 4 else "low"
        ranked = sorted(cves, key=lambda c: -c[1])
        for d, e in hits:
            f = _f("NG-CVE", sev, "Known CVE", d, f"{len(cves)} known CVE(s) mention {key}",
                   "Keyword match against the NIST NVD; confirm each applies to this exact product/build. Top: "
                   + "; ".join(f"{cid} (CVSS {score}) {desc[:120]}" for cid, score, desc in ranked[:3]),
                   "Update this device/software to the latest version.", e["port"], e["banner"],
                   "possible", [c[0] for c in ranked])
            f["cvss"] = top
            findings.append(f)
    return findings


def _cvss(cve):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in cve.get("metrics", {}).get(key, []):
            return float(m["cvssData"]["baseScore"])
    return 0.0


def _desc(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


# ----------------------------------------------------------------- scoring ---

SEVERITY_CAP = {"critical": 100, "high": 45, "medium": 28, "low": 10, "info": 0}


def _points(findings):
    """Weighted penalty; each severity is capped so many low issues can't outweigh one critical."""
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + \
            SEVERITY_PENALTY[f["severity"]] * CONFIDENCE_FACTOR.get(f["confidence"], 1)
    return sum(min(v, SEVERITY_CAP[s]) for s, v in by_sev.items())


def device_risk(device, findings):
    mine = [f for f in findings if f["ip"] == device["ip"]]
    counts = {s: sum(1 for f in mine if f["severity"] == s) for s in SEVERITY_ORDER}
    worst = next((s for s in SEVERITY_ORDER[:4] if counts[s]), None)
    status = "vulnerable" if worst in ("critical", "high") else "warning" if worst in ("medium", "low") else "secure"
    return {"level": worst or "secure", "status": status, "counts": counts,
            "score": max(0, round(100 - _points(mine))), "findings": len(mine)}


def analyze(wifi, devices, extra, cve=False, log=None):
    findings = check_wifi(wifi) + check_devices(devices, extra)
    if cve:
        findings += cve_lookup(devices, log=log)
    seen, unique = set(), []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["ip"] or ""))
    return unique


def score(findings):
    points = max(0, round(100 - _points(findings)))
    grade = "A" if points >= 90 else "B" if points >= 75 else "C" if points >= 60 else "D" if points >= 40 else "F"
    status = "Good" if points >= 75 else "Moderate" if points >= 50 else "At risk"
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    by_cat = {c: sum(1 for f in findings if f["category"] == c) for c in CATEGORIES}
    # What the score would be after fixing every critical and high finding (shown as motivation).
    rest = [f for f in findings if f["severity"] not in ("critical", "high")]
    potential = max(0, round(100 - _points(rest)))
    return {"score": points, "grade": grade, "status": status, "counts": counts, "by_category": by_cat,
            "potential": potential}
