import pytest

import app as netguard


@pytest.fixture
def client():
    netguard.app.config["TESTING"] = True
    return netguard.app.test_client()


def test_index_embeds_token_and_sets_csp(client):
    r = client.get("/")
    assert r.status_code == 200
    assert netguard.API_TOKEN.encode() in r.data
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_post_without_token_is_rejected(client):
    r = client.post("/api/settings", json={"threads": 50})
    assert r.status_code == 403


def test_post_with_token_is_accepted(client):
    r = client.post("/api/settings", json={"threads": 50}, headers={"X-NetGuard-Token": netguard.API_TOKEN})
    assert r.status_code == 200 and r.get_json()["threads"] == 50


def test_foreign_host_header_is_rejected(client):
    # DNS rebinding: attacker.com resolving to 127.0.0.1 still sends Host: attacker.com
    r = client.get("/api/settings", headers={"Host": "attacker.example:5000"})
    assert r.status_code == 403


def test_scan_requires_terms_then_rejects_public_target(client):
    h = {"X-NetGuard-Token": netguard.API_TOKEN}
    netguard.db.save_settings({"accepted_terms": ""}, internal=True)
    r = client.post("/api/scan", json={"mode": "quick", "target": "192.168.1.0/24"}, headers=h)
    assert r.status_code == 403 and "terms" in r.get_json()["error"]
    # accepted_terms can't be smuggled in through the normal settings endpoint
    client.post("/api/settings", json={"accepted_terms": "yes"}, headers=h)
    assert not client.get("/api/info").get_json()["terms_accepted"]
    assert client.post("/api/terms/accept", headers=h).status_code == 200
    r = client.post("/api/scan", json={"mode": "quick", "target": "8.8.8.0/24"}, headers=h)
    assert r.status_code == 400 and "private" in r.get_json()["error"]


def test_invalid_settings_rejected(client):
    r = client.post("/api/settings", json={"authorized_networks": "not-a-cidr"},
                    headers={"X-NetGuard-Token": netguard.API_TOKEN})
    assert r.status_code == 400
