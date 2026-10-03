"""Licensing, trial, Pro gating, scheduler, notifications, secrets and sites."""
import base64
from datetime import date, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import app as netguard
from scanner import db, licensing, notify, scheduler, secretstore

H = {"X-NetGuard-Token": netguard.API_TOKEN}


@pytest.fixture
def test_keys(monkeypatch):
    """Swap in a throwaway key pair so tests never need the seller's private key."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(licensing, "PUBLIC_KEY_B64", base64.b64encode(pub).decode())
    return priv


def _key(priv, **kw):
    payload = {"lic": "TEST1", "name": "Test User", "email": "t@example.com", "edition": "pro",
               "seats": 1, "issued": "2026-01-01", "exp": None, **kw}
    return licensing.make_key(payload, priv)


@pytest.fixture
def client():
    netguard.app.config["TESTING"] = True
    db.save_settings({"license_key": "", "trial_started": "", "accepted_terms": "x"}, internal=True)
    db.save_settings({"schedule_enabled": False, "email_enabled": False, "telegram_enabled": False,
                      "brand_company": "", "brand_contact": ""})
    for s in db.list_sites():
        db.delete_site(s["id"])
    return netguard.app.test_client()


# --------------------------------------------------------------- licences ---

def test_valid_key_roundtrip(test_keys):
    assert licensing.parse_key(_key(test_keys))["name"] == "Test User"


def test_tampered_key_rejected(test_keys):
    key = _key(test_keys)
    payload, sig = key[4:].split(".")
    forged = base64.urlsafe_b64encode(base64.urlsafe_b64decode(payload + "==").replace(b"Test User", b"Evil User"))
    with pytest.raises(ValueError, match="not valid"):
        licensing.parse_key("NG1-" + forged.decode().rstrip("=") + "." + sig)


def test_key_from_other_signer_rejected(test_keys):
    with pytest.raises(ValueError):
        licensing.parse_key(_key(Ed25519PrivateKey.generate()))


@pytest.mark.parametrize("junk", ["", "hello", "NG1-abc", "NG1-@@@.###"])
def test_garbage_keys_rejected(junk, test_keys):
    with pytest.raises(ValueError):
        licensing.parse_key(junk)


def test_status_license_expired_and_trial(test_keys):
    today = date(2026, 6, 1)
    s = {"license_key": _key(test_keys, exp="2026-12-31"), "trial_started": ""}
    st = licensing.status(s, today)
    assert st["edition"] == "pro" and st["source"] == "license" and st["license"]["days_left"] == 213
    s["license_key"] = _key(test_keys, exp="2026-05-01")
    assert licensing.status(s, today)["edition"] == "free"
    s = {"license_key": "", "trial_started": "2026-05-25T10:00:00"}
    assert licensing.status(s, today)["days_left"] == 7
    s["trial_started"] = "2026-05-01T10:00:00"
    assert licensing.status(s, today)["source"] == "trial_ended"


# ----------------------------------------------------------------- gating ---

def test_free_edition_blocks_pro_settings(client):
    r = client.post("/api/settings", json={"schedule_enabled": True}, headers=H)
    assert r.status_code == 402 and r.get_json()["pro_required"]
    r = client.post("/api/settings", json={"brand_company": "Acme IT"}, headers=H)
    assert r.status_code == 402


def test_trial_unlocks_pro_once(client):
    assert client.post("/api/license/trial", headers=H).get_json()["source"] == "trial"
    assert client.post("/api/license/trial", headers=H).status_code == 409
    r = client.post("/api/settings", json={"schedule_enabled": True, "schedule_time": "02:30"}, headers=H)
    assert r.status_code == 200 and r.get_json()["schedule_enabled"] is True


def test_activate_license_via_api(client, test_keys):
    assert client.post("/api/license/activate", json={"key": "nope"}, headers=H).status_code == 400
    r = client.post("/api/license/activate", json={"key": _key(test_keys)}, headers=H)
    assert r.status_code == 200 and r.get_json()["source"] == "license"
    # The licence key itself never comes back through the settings API
    assert "license_key" not in client.get("/api/settings").get_json()


def test_internal_keys_not_settable(client):
    client.post("/api/settings", json={"trial_started": "2099-01-01T00:00:00", "license_key": "x"}, headers=H)
    s = db.get_settings()
    assert s["trial_started"] == "" and s["license_key"] == ""


def test_free_site_limit(client):
    assert client.post("/api/sites", json={"name": "Home", "cidr": "192.168.1.0/24"}, headers=H).status_code == 200
    assert client.post("/api/sites", json={"name": "Office", "cidr": "10.0.0.0/24"}, headers=H).status_code == 402
    assert client.post("/api/sites", json={"name": "Bad", "cidr": "8.8.8.0/24"}, headers=H).status_code in (400, 402)


def test_settings_validation(client):
    client.post("/api/license/trial", headers=H)
    for bad in ({"schedule_time": "25:00"}, {"brand_color": "red"}, {"email_to": "not-an-email"},
                {"telegram_token": "abc"}, {"schedule_hours": 5}):
        assert client.post("/api/settings", json=bad, headers=H).status_code == 400, bad


# --------------------------------------------------------------- secrets ---

def test_secret_roundtrip_and_masking(client):
    assert secretstore.unprotect(secretstore.protect("p@ss word")) == "p@ss word"
    client.post("/api/license/trial", headers=H)
    client.post("/api/settings", json={"smtp_password": "hunter2"}, headers=H)
    assert db.get_settings()["smtp_password"] == "hunter2"
    assert client.get("/api/settings").get_json()["smtp_password"] == db.SECRET_MASK
    raw = db._query("SELECT value FROM settings WHERE key='smtp_password'")[0]["value"]
    assert "hunter2" not in raw  # encrypted at rest
    client.post("/api/settings", json={"smtp_password": db.SECRET_MASK}, headers=H)  # mask = unchanged
    assert db.get_settings()["smtp_password"] == "hunter2"


# -------------------------------------------------------------- scheduler ---

def _sched(**kw):
    return {"schedule_enabled": True, "schedule_frequency": "daily", "schedule_time": "03:00",
            "schedule_weekday": 6, "schedule_hours": 6, "schedule_mode": "quick", "last_scheduled_run": "", **kw}


def test_daily_slots():
    now = datetime(2026, 10, 3, 15, 20)  # Saturday
    assert scheduler.previous_slot(_sched(), now) == datetime(2026, 10, 3, 3, 0)
    assert scheduler.next_slot(_sched(), now) == datetime(2026, 10, 4, 3, 0)


def test_weekly_and_hourly_slots():
    now = datetime(2026, 10, 3, 15, 20)  # Saturday; Sunday = 6
    assert scheduler.next_slot(_sched(schedule_frequency="weekly"), now) == datetime(2026, 10, 4, 3, 0)
    assert scheduler.previous_slot(_sched(schedule_frequency="weekly"), now) == datetime(2026, 9, 27, 3, 0)
    assert scheduler.next_slot(_sched(schedule_frequency="hourly"), now) == datetime(2026, 10, 3, 18, 0)


def test_due_runs_once_per_slot():
    now = datetime(2026, 10, 3, 15, 20)
    ran = []
    state = _sched(last_scheduled_run="2026-10-02T03:05:00")
    sch = scheduler.Scheduler(lambda: state, lambda ts: state.update(last_scheduled_run=ts),
                              lambda s: True, ran.append)
    assert sch.tick(now) is True and ran == ["quick"]
    assert sch.tick(now + timedelta(minutes=1)) is False  # same slot: not again
    state["schedule_enabled"] = False
    assert sch.tick(now + timedelta(days=1)) is False


def test_scheduler_requires_pro():
    state = _sched()
    sch = scheduler.Scheduler(lambda: state, lambda ts: None, lambda s: False, lambda m: None)
    assert sch.tick(datetime(2026, 10, 3, 15, 20)) is False


# ---------------------------------------------------------- notifications ---

def test_notify_selection_and_dispatch(monkeypatch):
    alerts = [{"severity": "high", "kind": "new_vulnerability", "title": "Telnet on router\r\nBcc: x", "detail": ""},
              {"severity": "low", "kind": "new_service", "title": "Port 80", "detail": ""},
              {"severity": "info", "kind": "scan_completed", "title": "done", "detail": ""}]
    assert [a["severity"] for a in notify.select(alerts, "high")] == ["high"]
    subject, body = notify.compose(notify.select(alerts, "low"), "Home")
    assert subject == "NetGuard: 2 new alerts on Home" and "\r" not in body and "Bcc: x" in body.splitlines()[0]
    sent = []
    monkeypatch.setattr(notify, "send_telegram", lambda s, text: sent.append(text))
    monkeypatch.setattr(notify, "send_email", lambda s, subj, b: (_ for _ in ()).throw(OSError("smtp down")))
    res = notify.dispatch(alerts, {"notify_min_severity": "high", "email_enabled": True, "telegram_enabled": True})
    assert res["telegram"] == "sent" and res["email"].startswith("failed") and len(sent) == 1
