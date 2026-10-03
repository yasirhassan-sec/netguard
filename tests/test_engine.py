import pytest

from scanner import network, ports, vulns, wifi


# ---------------------------------------------------------------- targets ---

def test_validate_target_accepts_private_ranges():
    assert str(network.validate_target("192.168.1.0/24")) == "192.168.1.0/24"
    assert str(network.validate_target("10.0.0.5")) == "10.0.0.5/32"


@pytest.mark.parametrize("bad", ["8.8.8.0/24", "192.168.0.0/16", "not-an-ip", "fe80::1/64"])
def test_validate_target_rejects_public_huge_or_invalid(bad):
    with pytest.raises(ValueError):
        network.validate_target(bad)


def test_validate_target_respects_authorized_networks():
    assert network.validate_target("192.168.1.10", "192.168.1.0/24")
    with pytest.raises(ValueError):
        network.validate_target("192.168.2.0/24", "192.168.1.0/24")


def test_parse_ports():
    assert ports.parse_ports("22, 80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert ports.parse_ports("70000,5") == [5]
    with pytest.raises(ValueError):
        ports.parse_ports("")


# ------------------------------------------------------------------ Wi-Fi ---

NETSH_NETWORKS = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36

SSID 2 : Cafe <script>
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:02
         Signal             : 28%
         Channel            : 6
"""


def test_netsh_network_parsing(monkeypatch):
    monkeypatch.setattr(wifi, "run_cmd", lambda *a, **k: (NETSH_NETWORKS, 0))
    rows, _ = wifi._windows_networks()
    assert [r["ssid"] for r in rows] == ["HomeNet", "Cafe <script>"]
    assert rows[0]["bssid"] == "aa:bb:cc:dd:ee:01" and rows[0]["signal"] == 92
    assert rows[1]["auth"] == "Open" and rows[1]["channel"] == "6"


@pytest.mark.parametrize("auth,enc,level", [
    ("Open", "None", "high"), ("WEP", "WEP", "high"), ("WPA-Personal", "TKIP", "medium"),
    ("WPA2-Personal", "CCMP", "low"), ("WPA3-Personal", "GCMP", "secure"),
])
def test_wifi_risk(auth, enc, level):
    assert vulns.wifi_risk(auth, enc)["level"] == level


def test_band_from_channel():
    assert wifi.band_from_channel("6") == "2.4 GHz"
    assert wifi.band_from_channel("149") == "5 GHz"


# ------------------------------------------------------------------ vulns ---

def _device(ip="192.168.1.1", ports_open=(), **kw):
    d = {"ip": ip, "mac": "aa:bb:cc:00:00:01", "vendor": "Test", "hostname": "", "is_self": False,
         "is_gateway": False, "ttl": 64, "open_ports": [], "upnp": [], "snmp": None, "type": "Unknown", "os": "Unknown"}
    d.update(kw)
    for p in ports_open:
        d["open_ports"].append({"port": p, "state": "open", "service": ports.service_name(p),
                                "version": "", "banner": "", "http": None})
    return d


def test_telnet_is_high():
    f = vulns.check_devices([_device(ports_open=[23])], {})
    assert [(x["rule"], x["severity"]) for x in f] == [("NG-TELNET", "high")]


def test_own_pc_port_blocked_by_firewall_is_info():
    me = _device("192.168.1.22", [1433, 445], is_self=True,
                 firewall={"profiles": ["Public"], "allowed": {445: {"rule": "SMB-In", "remote": "LocalSubnet"}}})
    f = {x["port"]: x for x in vulns.check_devices([me], {})}
    assert f[445]["severity"] == "medium" and "SMB-In" in f[445]["evidence"]
    assert f[1433]["severity"] == "info" and "blocks" in f[1433]["title"]


def test_regresshion_version_range():
    d = _device(ports_open=[22])
    d["open_ports"][0]["banner"] = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
    rules = {x["rule"] for x in vulns.check_devices([d], {})}
    assert "NG-OPENSSH-REGRESSHION" in rules


def test_smb1_and_snmp_findings():
    d = _device(ports_open=[445], snmp="RouterOS")
    rules = {x["rule"] for x in vulns.check_devices([d], {d["ip"]: {"smb1": True, "tls_legacy": {}}})}
    assert {"NG-SMB1", "NG-SNMP-PUBLIC", "NG-SMB"} <= rules


def test_score_caps_low_findings():
    lows = [{"severity": "low", "confidence": "confirmed", "category": "Encryption"}] * 20
    assert vulns.score(lows)["score"] == 90  # low findings capped at 10 points
    crit = [{"severity": "critical", "confidence": "confirmed", "category": "Exposed Service"}] * 5
    assert vulns.score(crit)["score"] == 0


def test_device_risk_status():
    d = _device()
    f = [{"ip": d["ip"], "severity": "high", "confidence": "confirmed"}]
    assert vulns.device_risk(d, f)["status"] == "vulnerable"
    assert vulns.device_risk(d, [])["status"] == "secure"
