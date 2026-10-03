"""Interfaces, gateway detection, host discovery (ping + ARP) and UPnP/SSDP discovery."""
import concurrent.futures as cf
import ipaddress
import platform
import re
import socket
import time

import psutil

from . import oui
from .utils import IS_WINDOWS, normalize_mac, run_cmd

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAX_HOSTS_PREFIX = 22  # refuse sweeps larger than a /22 (1022 hosts)


def local_ip():
    """IP of the interface that carries the default route (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def get_interfaces():
    stats = psutil.net_if_stats()
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        mac = next((normalize_mac(a.address) for a in addrs if a.family == psutil.AF_LINK), None)
        st = stats.get(name)
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            if a.address.startswith(("127.", "169.254.")):
                continue
            net = ipaddress.IPv4Interface(f"{a.address}/{a.netmask}").network
            result.append({
                "name": name,
                "ip": a.address,
                "netmask": a.netmask,
                "cidr": str(net),
                "mac": mac,
                "up": bool(st and st.isup),
                "speed_mbps": st.speed if st else 0,
            })
    return result


def get_gateway():
    if IS_WINDOWS:
        out, _ = run_cmd(["route", "print", "-4", "0.0.0.0"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    else:
        out, _ = run_cmd(["ip", "route", "show", "default"])
        m = re.search(r"default via (\S+)", out)
        if m:
            return m.group(1)
    return None


def default_target():
    ip = local_ip()
    if not ip:
        return None
    for iface in get_interfaces():
        if iface["ip"] == ip:
            net = ipaddress.ip_network(iface["cidr"])
            if net.prefixlen >= MAX_HOSTS_PREFIX:
                return str(net)
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def validate_target(text, authorized=""):
    """Only private IPv4 ranges of reasonable size: this is a *home* network scanner.

    authorized: optional comma-separated CIDRs the target must fall inside (Settings).
    """
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise ValueError("Enter an IP or CIDR range, e.g. 192.168.1.0/24")
    if net.version != 4:
        raise ValueError("Only IPv4 ranges are supported.")
    if not net.is_private:
        raise ValueError("Only private (home/LAN) address ranges may be scanned.")
    if net.prefixlen < MAX_HOSTS_PREFIX:
        raise ValueError(f"Range too large; use /{MAX_HOSTS_PREFIX} or smaller.")
    allowed = [a.strip() for a in (authorized or "").split(",") if a.strip()]
    if allowed:
        try:
            nets = [ipaddress.ip_network(a, strict=False) for a in allowed]
        except ValueError:
            raise ValueError("Authorized networks in Settings contain an invalid CIDR.")
        if not any(net.subnet_of(a) for a in nets if a.version == 4):
            raise ValueError(f"{net} is not in your authorized networks ({', '.join(allowed)}).")
    return net


def _ping(ip):
    """Return the reply TTL (used for OS fingerprinting), or None if there was no reply."""
    if IS_WINDOWS:
        out, _ = run_cmd(["ping", "-n", "1", "-w", "700", ip], timeout=5)
    else:
        out, _ = run_cmd(["ping", "-c", "1", "-W", "1", ip], timeout=5)
    # Windows returns 0 even for "Destination host unreachable", so look for a real reply.
    m = re.search(r"ttl=(\d+)", out, re.I)
    return int(m.group(1)) if m else None


def read_arp_table():
    if IS_WINDOWS:
        out, _ = run_cmd(["arp", "-a"])
    else:
        out, rc = run_cmd(["ip", "neigh"])
        if rc != 0:
            out, _ = run_cmd(["arp", "-an"])
    table = {}
    for line in out.splitlines():
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        mac = normalize_mac(mac_m.group(0))
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith("01:00:5e"):
            continue
        table[ip_m.group(1)] = mac
    return table


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def discover(net, my_ip=None, progress=None, include_all=False):
    """Ping-sweep the range, then merge in the ARP cache (catches hosts that ignore ping).

    include_all keeps every address even without a reply (used for single-device scans).
    """
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    ttls = {}
    with cf.ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_ping, h): h for h in hosts}
        for i, fut in enumerate(cf.as_completed(futures), 1):
            if fut.result() is not None:
                ttls[futures[fut]] = fut.result()
            if progress and (i % 8 == 0 or i == len(futures)):
                progress(i / len(futures))

    alive = set(ttls)
    arp = read_arp_table()
    alive |= {ip for ip in arp if ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address)}
    if include_all:
        alive |= set(hosts)

    own_macs = {i["ip"]: i["mac"] for i in get_interfaces()}
    if my_ip and ipaddress.ip_address(my_ip) in net:
        alive.add(my_ip)

    ordered = sorted(alive, key=lambda ip: ipaddress.ip_address(ip))
    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        names = dict(zip(ordered, pool.map(_reverse_dns, ordered)))

    devices = []
    for ip in ordered:
        mac = arp.get(ip) or own_macs.get(ip)
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": oui.vendor(mac),
            "hostname": names.get(ip, ""),
            "is_self": ip == my_ip,
            "is_gateway": False,
            "ttl": ttls.get(ip),
            "responds_to_ping": ip in ttls,
            "open_ports": [],
            "upnp": [],
            "snmp": None,
            "type": "Unknown",
            "os": "Unknown",
        })
    return devices


def ssdp_discover(my_ip, wait=3.0):
    """Send a UPnP M-SEARCH and collect replies: {ip: [{server, st, location}]}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if my_ip:
            sock.bind((my_ip, 0))
        sock.settimeout(0.5)
        for _ in range(2):
            sock.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                data, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            headers = {}
            for line in data.decode(errors="replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            entry = {"server": headers.get("server", ""), "st": headers.get("st", ""),
                     "location": headers.get("location", "")}
            if entry not in found.setdefault(ip, []):
                found[ip].append(entry)
    except OSError:
        pass
    finally:
        sock.close()
    return found


def guess_os(device):
    """Best-effort OS fingerprint from banners, open ports and the ping TTL."""
    ports = {p["port"] for p in device["open_ports"]}
    banners = " ".join(p["banner"] for p in device["open_ports"]).lower()
    snmp = (device.get("snmp") or "").lower()
    for word, name in (("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"),
                       ("raspbian", "Linux (Raspberry Pi OS)"), ("synology", "Linux (Synology DSM)"),
                       ("microsoft-iis", "Windows"), ("microsoft-httpapi", "Windows"),
                       ("routeros", "MikroTik RouterOS"), ("openwrt", "Linux (OpenWrt)")):
        if word in banners or word in snmp:
            return name
    if device["is_self"]:
        return f"{platform.system()} {platform.release()}"
    if ports & {135, 139, 445, 3389}:
        return "Windows"
    if 62078 in ports:
        return "iOS / iPadOS"
    if 5555 in ports:
        return "Android"
    if 548 in ports:
        return "macOS"
    ttl = device.get("ttl")
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        if "Private (randomized)" in device["vendor"]:
            return "Android / iOS"
        return "Linux / Unix" if ports & {22} or device["is_gateway"] else "Linux / Unix / Embedded"
    if ttl <= 128:
        return "Windows"
    return "Network device (embedded)"


def guess_type(device):
    ports = {p["port"] for p in device["open_ports"]}
    text = " ".join([device["vendor"], device["hostname"],
                     " ".join(u["server"] + " " + u["st"] for u in device["upnp"])]).lower()
    if device["is_self"]:
        return "This computer"
    if device["is_gateway"]:
        return "Router / gateway"
    if ports & {9100, 631, 515} or "printer" in text:
        return "Printer"
    if 554 in ports or "camera" in text or "ipcam" in text:
        return "Camera"
    if 8009 in ports or "chromecast" in text or "mediarenderer" in text or "roku" in text:
        return "TV / streaming"
    if 5555 in ports or "android" in text:
        return "Android device"
    if 62078 in ports:
        return "Phone / tablet"
    if 32400 in ports or "mediaserver" in text or ports & {2049, 548}:
        return "Media / NAS"
    if ports & {135, 139, 445, 3389}:
        return "Windows PC"
    if "iphone" in text or "ipad" in text or "apple" in text:
        return "Apple device"
    if "Private (randomized)" in device["vendor"]:
        return "Phone / laptop"
    if 22 in ports:
        return "Linux / server"
    return "Unknown"
