"""Safe, non-exploiting probes: banners, HTTP headers, TLS versions, SMBv1, anonymous FTP, SNMP.

Every probe only asks a service what it supports; nothing tries to exploit a weakness.
"""
import re
import socket
import ssl
import struct


def _clean(data):
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"[^\x20-\x7e\n]", "", text).strip()
    return " | ".join(l.strip() for l in text.splitlines() if l.strip())[:200]


def raw_banner(ip, port, timeout=2.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port == 6379:
                s.sendall(b"PING\r\n")
            return _clean(s.recv(1024))
    except OSError:
        return ""


def _tls_context(min_version=None, max_version=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # home devices almost always use self-signed certificates
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.minimum_version = min_version or ssl.TLSVersion.TLSv1
    if max_version:
        ctx.maximum_version = max_version
    return ctx


def http_info(ip, port, tls=False, timeout=3.0):
    """GET / and return status, headers, title, TLS version. None if it isn't HTTP."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            sock, tls_version = raw, None
            if tls:
                sock = _tls_context().wrap_socket(raw)
                tls_version = sock.version()
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetGuard\r\n\r\n".encode())
            data = b""
            try:
                while len(data) < 32768:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
    except (OSError, ssl.SSLError):
        return None
    text = data.decode("utf-8", errors="replace")
    if not text.startswith("HTTP/"):
        return None
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    m = re.match(r"HTTP/\S+\s+(\d+)", lines[0])
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = " ".join(title.group(1).split())[:80] if title else ""
    parts = [lines[0].strip()]
    if tls_version:
        parts.insert(0, f"[{tls_version}]")
    if headers.get("server"):
        parts.append("Server: " + headers["server"])
    if title:
        parts.append("Title: " + title)
    login = bool(re.search(r"type=[\"']?password|login|sign in|admin", body, re.I)) or \
        "www-authenticate" in headers
    return {"status": int(m.group(1)) if m else None, "headers": headers, "title": title,
            "tls": tls_version, "server": headers.get("server", ""), "login_form": login,
            "banner": " | ".join(parts)[:250]}


def tls_legacy(ip, port, timeout=3.0):
    """Return 'TLSv1'/'TLSv1.1' if the server still accepts a deprecated protocol version."""
    try:
        ctx = _tls_context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as s:
                return s.version()
    except (OSError, ssl.SSLError, ValueError):
        return None


def smb1_enabled(ip, timeout=3.0):
    """Send an SMB1 NEGOTIATE offering only 'NT LM 0.12'. True if the server accepts SMBv1."""
    dialects = b"\x02NT LM 0.12\x00"
    header = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18" + b"\x53\xc8"
              + b"\x00" * 12 + b"\x00\x00" + b"\xff\xfe" + b"\x00\x00" + b"\x00\x00")
    smb = header + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    packet = b"\x00" + len(smb).to_bytes(3, "big") + smb
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            resp = s.recv(1024)
    except OSError:
        return False  # modern Windows simply drops the connection when SMBv1 is disabled
    # Needs an SMB1 reply with STATUS_SUCCESS and at least one parameter word.
    if len(resp) < 39 or resp[4:8] != b"\xffSMB" or resp[9:13] != b"\x00" * 4 or resp[36] == 0:
        return False
    dialect_index = struct.unpack("<H", resp[37:39])[0]
    return dialect_index != 0xFFFF


def ftp_anonymous(ip, timeout=4.0):
    """True if the FTP server accepts the public 'anonymous' login."""
    try:
        with socket.create_connection((ip, 21), timeout=timeout) as s:
            s.settimeout(timeout)
            f = s.makefile("rb")
            if not f.readline().startswith(b"220"):
                return False
            s.sendall(b"USER anonymous\r\n")
            line = f.readline()
            if line.startswith(b"230"):
                return True
            if not line.startswith(b"331"):
                return False
            s.sendall(b"PASS netguard@example.com\r\n")
            ok = f.readline().startswith(b"230")
            s.sendall(b"QUIT\r\n")
            return ok
    except OSError:
        return False


# SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0) with community "public".
_SNMP_GET = bytes.fromhex(
    "302602010004067075626c6963a01902010102010002010030"
    "0e300c06082b060102010101000500"
)
_SYSDESCR_OID = bytes.fromhex("06082b06010201010100")


def snmp_public(ip, timeout=1.0):
    """Return sysDescr if the device answers SNMP with the default 'public' community."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_SNMP_GET, (ip, 161))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()
    idx = data.find(_SYSDESCR_OID)
    if idx < 0:
        return "(responded)"
    rest = data[idx + len(_SYSDESCR_OID):]
    if len(rest) < 2 or rest[0] != 0x04:
        return "(responded)"
    length, start = rest[1], 2
    if length & 0x80:  # long-form BER length
        n = length & 0x7F
        length, start = int.from_bytes(rest[2:2 + n], "big"), 2 + n
    return rest[start:start + length].decode("utf-8", errors="replace")[:200] or "(responded)"
