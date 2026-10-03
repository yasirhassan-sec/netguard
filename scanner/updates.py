"""Update checker. Fetches a small JSON file you host, e.g. on your website or GitHub Pages:

    {"version": "3.1.0", "url": "https://your-site.example/download", "notes": "What's new"}

Only the request itself is sent (no scan data). Set UPDATE_URL before release, or override it
with the NETGUARD_UPDATE_URL environment variable. Empty = update checks are off.
"""
import json
import os
import re
import time
import urllib.request

from . import __version__

UPDATE_URL = os.environ.get("NETGUARD_UPDATE_URL", "")
_cache = {"at": 0, "data": None}


def _ver(text):
    return tuple(int(x) for x in re.findall(r"\d+", str(text))[:3])


def check(force=False):
    if not UPDATE_URL.startswith("https://"):
        return {"enabled": False, "current": __version__}
    if not force and _cache["data"] and time.time() - _cache["at"] < 6 * 3600:
        return _cache["data"]
    try:
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": f"NetGuard/{__version__}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            info = json.loads(resp.read(65536))
        latest = str(info.get("version", ""))
        url = str(info.get("url", ""))
        data = {"enabled": True, "current": __version__, "latest": latest,
                "available": _ver(latest) > _ver(__version__),
                "url": url if url.startswith("https://") else "", "notes": str(info.get("notes", ""))[:500]}
    except Exception as exc:
        data = {"enabled": True, "current": __version__, "error": f"Update check failed: {exc}"}
    _cache.update(at=time.time(), data=data)
    return data
