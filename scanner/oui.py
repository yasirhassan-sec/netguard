"""MAC address -> manufacturer lookup using the IEEE OUI registry (downloaded on demand)."""
import csv
import os
import urllib.request

from .paths import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "oui.csv")
IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"

_cache = None


def _load():
    global _cache
    if _cache is not None:
        return _cache
    _cache = {}
    if os.path.exists(DB_PATH):
        with open(DB_PATH, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                prefix = (row.get("Assignment") or "").strip().upper()
                if len(prefix) == 6:
                    _cache[prefix] = (row.get("Organization Name") or "").strip()
    return _cache


def db_status():
    return {"installed": os.path.exists(DB_PATH), "entries": len(_load())}


def update_db():
    """Download the IEEE OUI registry (~3 MB) into data/oui.csv."""
    global _cache
    os.makedirs(DATA_DIR, exist_ok=True)
    req = urllib.request.Request(IEEE_URL, headers={"User-Agent": "Mozilla/5.0 home-netscan"})
    tmp = DB_PATH + ".part"
    with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as f:
        f.write(resp.read())
    os.replace(tmp, DB_PATH)
    _cache = None
    return db_status()


def is_randomized(mac):
    """Phones and laptops use 'locally administered' random MACs for privacy."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def vendor(mac):
    if not mac:
        return "Unknown"
    if is_randomized(mac):
        return "Private (randomized) MAC"
    name = _load().get(mac.replace(":", "")[:6].upper())
    return name or "Unknown"
