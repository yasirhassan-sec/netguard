"""TCP port scanning and service/version detection."""
import concurrent.futures as cf
import re
import socket

from . import probes

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 515: "LPD", 548: "AFP", 554: "RTSP", 631: "IPP", 873: "rsync", 1080: "SOCKS",
    1433: "MSSQL", 1883: "MQTT", 2049: "NFS", 2375: "Docker API", 3000: "HTTP", 3306: "MySQL",
    3389: "RDP", 5000: "UPnP/HTTP", 5432: "PostgreSQL", 5555: "ADB", 5900: "VNC", 6379: "Redis",
    7547: "TR-069", 8000: "HTTP", 8008: "HTTP", 8009: "Chromecast", 8080: "HTTP-proxy",
    8081: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9000: "HTTP", 9100: "JetDirect",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 49152: "UPnP",
    62078: "iPhone-sync",
}

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9200, 32400, 49152}
HTTPS_PORTS = {443, 8443}

MODES = {
    "quick": {"label": "Quick Scan", "desc": "Host discovery, ~50 common ports, basic checks"},
    "full": {"label": "Full Scan", "desc": "Ports 1-1024 + common, services, configuration and vulnerability checks"},
    "single": {"label": "Single Device", "desc": "Full checks against one IP address"},
    "custom": {"label": "Custom Scan", "desc": "Your own port list and choice of checks"},
}

VERSION_RE = re.compile(r"([A-Za-z][\w.+-]*?)[/_ -]v?(\d+(?:\.\d+)+[a-z]?\d*)")


def parse_ports(text, limit=65535):
    """'22,80,8000-8100' -> sorted list of ports."""
    ports = set()
    for part in (text or "").replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        raise ValueError("No valid ports given")
    return sorted(ports)[:limit]


def ports_for_mode(mode, custom=""):
    if mode == "quick":
        return sorted(COMMON_PORTS)
    if mode in ("full", "single"):
        return sorted(set(COMMON_PORTS) | set(range(1, 1025)))
    return parse_ports(custom)


def service_name(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "unknown"


def _is_open(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_devices(devices, ports, timeout=0.6, threads=200, progress=None):
    """Connect scan. Fills device['open_ports'] in place and returns ports checked."""
    tasks = [(d, p) for d in devices for p in ports]
    if not tasks:
        return 0
    with cf.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_is_open, d["ip"], p, timeout): (d, p) for d, p in tasks}
        for i, fut in enumerate(cf.as_completed(futures), 1):
            if fut.result():
                d, p = futures[fut]
                d["open_ports"].append({"port": p, "state": "open", "service": service_name(p),
                                        "version": "", "banner": "", "http": None})
            if progress and i % 50 == 0:
                progress(i / len(futures))
    for d in devices:
        d["open_ports"].sort(key=lambda e: e["port"])
    return len(tasks)


def _version_from(text):
    server = re.search(r"server:\s*([^|]+)", text, re.I)
    if server:
        source = server.group(1)
    elif text.startswith(("HTTP/", "[TLS")):
        return ""  # HTTP without a Server header: the status line's "HTTP/1.1" isn't a product version
    else:
        source = text
    m = VERSION_RE.search(source)
    if m:
        return f"{m.group(1).rstrip('-_')} {m.group(2)}"
    return server.group(1).strip()[:40] if server else ""


def _detect_one(ip, entry):
    port = entry["port"]
    if port in HTTPS_PORTS or port in HTTP_PORTS:
        info = probes.http_info(ip, port, tls=port in HTTPS_PORTS)
        if info is None and port not in HTTPS_PORTS:
            info = probes.http_info(ip, port, tls=True)  # some "HTTP" ports actually speak TLS
        if info:
            entry["http"] = info
            entry["banner"] = info["banner"]
            if info["tls"]:
                entry["service"] = "HTTPS"
    else:
        entry["banner"] = probes.raw_banner(ip, port)
    entry["version"] = _version_from(entry["banner"])


def detect_services(devices, progress=None):
    items = [(d["ip"], e) for d in devices for e in d["open_ports"]]
    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(_detect_one, ip, e) for ip, e in items]
        for i, _ in enumerate(cf.as_completed(futures), 1):
            if progress:
                progress(i / len(futures))
