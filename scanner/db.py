"""SQLite persistence: scans, device inventory, alerts, audit log and settings."""
import json
import os
import sqlite3
import threading
from datetime import datetime

from .paths import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "netguard.db")

DEFAULT_SETTINGS = {
    "timeout_ms": 600,          # TCP connect timeout per port
    "threads": 200,             # concurrent connection attempts
    "custom_ports": "1-1024",   # used by the Custom scan mode
    "service_detection": True,
    "vuln_checks": True,
    "config_checks": True,
    "cve_lookup": False,        # online NVD lookup (sends product/version strings to NIST)
    "authorized_networks": "",  # comma-separated CIDRs; empty = any private range
    "wifi_sampling": True,
    "accepted_terms": "",       # timestamp the user confirmed authorised-use terms (first run)
}

_lock = threading.Lock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT, finished TEXT, target TEXT, mode TEXT, status TEXT,
    devices INTEGER DEFAULT 0, findings INTEGER DEFAULT 0, duration REAL DEFAULT 0,
    summary TEXT, result TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    key TEXT PRIMARY KEY, ip TEXT, mac TEXT, hostname TEXT, vendor TEXT, type TEXT, os TEXT,
    risk TEXT, first_seen TEXT, last_seen TEXT, last_scan_id INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, severity TEXT, kind TEXT,
    title TEXT, detail TEXT, read INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
"""


def now():
    return datetime.now().isoformat(timespec="seconds")


def _db():
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
    return _conn


def _exec(sql, args=()):
    with _lock:
        cur = _db().execute(sql, args)
        _db().commit()
        return cur.lastrowid


def _query(sql, args=()):
    with _lock:
        return [dict(r) for r in _db().execute(sql, args).fetchall()]


# --------------------------------------------------------------- audit ---

def audit(action, detail=""):
    _exec("INSERT INTO audit (ts, action, detail) VALUES (?, ?, ?)", (now(), action, detail))


def list_audit(limit=300):
    return _query("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))


# -------------------------------------------------------------- alerts ---

def add_alert(severity, kind, title, detail=""):
    _exec("INSERT INTO alerts (ts, severity, kind, title, detail) VALUES (?, ?, ?, ?, ?)",
          (now(), severity, kind, title, detail))


def list_alerts(limit=200):
    return _query("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))


def unread_alerts():
    return _query("SELECT COUNT(*) AS n FROM alerts WHERE read = 0")[0]["n"]


def mark_alerts_read(ids=None):
    if ids:
        marks = ",".join("?" * len(ids))
        _exec(f"UPDATE alerts SET read = 1 WHERE id IN ({marks})", tuple(ids))
    else:
        _exec("UPDATE alerts SET read = 1")


def clear_alerts():
    _exec("DELETE FROM alerts")


# --------------------------------------------------------------- scans ---

def create_scan(target, mode):
    return _exec("INSERT INTO scans (started, target, mode, status) VALUES (?, ?, ?, 'running')",
                 (now(), target, mode))


def finish_scan(scan_id, result):
    s = result["summary"]
    _exec("UPDATE scans SET finished=?, status='completed', devices=?, findings=?, duration=?, "
          "summary=?, result=? WHERE id=?",
          (result["meta"]["finished"], s["devices"], len(result["findings"]),
           result["meta"]["duration_s"], json.dumps(s), json.dumps(result), scan_id))


def fail_scan(scan_id, error):
    _exec("UPDATE scans SET finished=?, status='failed', error=? WHERE id=?", (now(), error, scan_id))


def list_scans(limit=100):
    rows = _query("SELECT id, started, finished, target, mode, status, devices, findings, duration, "
                  "summary, error FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        r["summary"] = json.loads(r["summary"]) if r["summary"] else None
    return rows


def get_result(scan_id=None):
    """Full result of a scan, or of the latest completed one."""
    if scan_id is None:
        rows = _query("SELECT id, result FROM scans WHERE status='completed' ORDER BY id DESC LIMIT 1")
    else:
        rows = _query("SELECT id, result FROM scans WHERE id=? AND status='completed'", (scan_id,))
    if not rows or not rows[0]["result"]:
        return None
    result = json.loads(rows[0]["result"])
    result["meta"]["scan_id"] = rows[0]["id"]
    return result


def previous_result(scan_id, target):
    rows = _query("SELECT id FROM scans WHERE status='completed' AND id < ? AND target=? "
                  "ORDER BY id DESC LIMIT 1", (scan_id, target))
    return get_result(rows[0]["id"]) if rows else None


def recent_results(limit=20):
    ids = _query("SELECT id FROM scans WHERE status='completed' ORDER BY id DESC LIMIT ?", (limit,))
    return [get_result(r["id"]) for r in ids]


# ------------------------------------------------------------- devices ---

def device_key(d):
    return d.get("mac") or d["ip"]


def known_device_keys():
    return {r["key"] for r in _query("SELECT key FROM devices")}


def upsert_devices(devices, scan_id, ts):
    with _lock:
        conn = _db()
        for d in devices:
            key = device_key(d)
            exists = conn.execute("SELECT 1 FROM devices WHERE key=?", (key,)).fetchone()
            if exists:
                conn.execute("UPDATE devices SET ip=?, mac=?, hostname=COALESCE(NULLIF(?, ''), hostname), "
                             "vendor=?, type=?, os=?, risk=?, last_seen=?, last_scan_id=? WHERE key=?",
                             (d["ip"], d["mac"], d["hostname"], d["vendor"], d["type"], d["os"],
                              d["risk"]["level"], ts, scan_id, key))
            else:
                conn.execute("INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             (key, d["ip"], d["mac"], d["hostname"], d["vendor"], d["type"], d["os"],
                              d["risk"]["level"], ts, ts, scan_id))
        conn.commit()


def list_devices():
    rows = _query("SELECT * FROM devices ORDER BY last_seen DESC")
    latest = _query("SELECT MAX(id) AS id FROM scans WHERE status='completed'")[0]["id"]
    for r in rows:
        r["online"] = r["last_scan_id"] == latest
    return rows


def get_device(key):
    rows = _query("SELECT * FROM devices WHERE key=?", (key,))
    return rows[0] if rows else None


# ------------------------------------------------------------ settings ---

def get_settings():
    stored = {r["key"]: json.loads(r["value"]) for r in _query("SELECT key, value FROM settings")}
    return {**DEFAULT_SETTINGS, **{k: v for k, v in stored.items() if k in DEFAULT_SETTINGS}}


def save_settings(values):
    clean = {}
    for key, default in DEFAULT_SETTINGS.items():
        if key not in values:
            continue
        v = values[key]
        if isinstance(default, bool):
            v = bool(v)
        elif isinstance(default, int):
            v = int(v)
        else:
            v = str(v).strip()
        clean[key] = v
        _exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(v)))
    return clean
