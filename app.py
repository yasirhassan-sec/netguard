"""NetGuard - Home Network Vulnerability Scanner (Flask app + REST API).

Run:  python app.py   then open http://127.0.0.1:5000
Only scan networks you own or have permission to test.
"""
import getpass
import hmac
import logging
import os
import secrets
import socket
import threading
from datetime import datetime

from flask import Flask, Response, abort, jsonify, render_template, request

from scanner import __version__, db, engine, network, oui, ports, report, wifi
from scanner.paths import RESOURCE_DIR, setup_logging

log = logging.getLogger("netguard")

app = Flask(__name__, template_folder=os.path.join(RESOURCE_DIR, "templates"),
            static_folder=os.path.join(RESOURCE_DIR, "static"))

# Random per-run secret. The page receives it in a <meta> tag and must send it back on every
# state-changing request, so other websites open in the browser can't drive the local API (CSRF).
API_TOKEN = secrets.token_urlsafe(32)
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

_job = None
_job_lock = threading.Lock()


@app.before_request
def _guard():
    # Reject requests whose Host isn't loopback: defeats DNS-rebinding attacks from web pages.
    host = (request.host or "").rsplit(":", 1)[0].lower()
    if host not in ALLOWED_HOSTS:
        abort(403)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("X-NetGuard-Token", "")
        if not hmac.compare_digest(sent, API_TOKEN):
            return jsonify({"error": "Missing or invalid security token. Reload the page."}), 403


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if resp.mimetype == "text/html" and request.path == "/":
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return resp


def _latest():
    return db.get_result()


@app.route("/")
def index():
    return render_template("index.html", api_token=API_TOKEN, version=__version__)


# ------------------------------------------------------------------ info ---

@app.get("/api/info")
def api_info():
    return jsonify({
        "interfaces": network.get_interfaces(),
        "local_ip": network.local_ip(),
        "gateway": network.get_gateway(),
        "default_target": network.default_target(),
        "oui": oui.db_status(),
        "user": getpass.getuser(),
        "hostname": socket.gethostname(),
        "modes": ports.MODES,
        "unread_alerts": db.unread_alerts(),
        "version": __version__,
        "terms_accepted": bool(db.get_settings()["accepted_terms"]),
    })


@app.get("/api/overview")
def api_overview():
    devices = db.list_devices()
    return jsonify({
        "result": _latest(),
        "scans": db.list_scans(6),
        "alerts": db.list_alerts(6),
        "unread_alerts": db.unread_alerts(),
        "inventory": {"total": len(devices), "online": sum(d["online"] for d in devices)},
    })


# ----------------------------------------------------------------- Wi-Fi ---

@app.get("/api/wifi")
def api_wifi():
    return jsonify(wifi.survey())


# ----------------------------------------------------------------- scans ---

@app.post("/api/scan")
def api_scan_start():
    global _job
    body = request.get_json(silent=True) or {}
    settings = db.get_settings()
    if not settings["accepted_terms"]:
        return jsonify({"error": "Please confirm the authorised-use terms before scanning."}), 403
    mode = body.get("mode", "quick")
    if mode not in ports.MODES:
        return jsonify({"error": "Unknown scan mode"}), 400
    target = (body.get("target") or network.default_target() or "").strip()
    if mode == "single":
        target = target.split("/")[0] + "/32"
    try:
        net = network.validate_target(target, settings["authorized_networks"])
        port_text = body.get("ports") or settings["custom_ports"]
        if mode == "custom":
            ports.parse_ports(port_text)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    options = {
        "timeout_ms": min(5000, max(100, settings["timeout_ms"])),
        "threads": min(500, max(10, settings["threads"])),
        "service_detection": body.get("service_detection", settings["service_detection"]),
        "config_checks": body.get("config_checks", settings["config_checks"]),
        "vuln_checks": body.get("vuln_checks", settings["vuln_checks"]),
        "cve_lookup": body.get("cve_lookup", settings["cve_lookup"]),
        "ports": port_text if mode == "custom" else "",
    }
    with _job_lock:
        if _job and _job.state == "running":
            return jsonify({"error": "A scan is already running"}), 409
        _job = engine.ScanJob(net, mode, options)
        threading.Thread(target=engine.run, args=(_job,), daemon=True).start()
    return jsonify(_job.to_dict()), 202


@app.get("/api/scan")
def api_scan_status():
    return jsonify(_job.to_dict() if _job else {"state": "idle"})


@app.get("/api/scans")
def api_scans():
    return jsonify(db.list_scans(200))


@app.get("/api/scans/<int:scan_id>")
def api_scan_result(scan_id):
    result = db.get_result(scan_id)
    return jsonify(result) if result else abort(404)


@app.get("/api/compare")
def api_compare():
    old, new = db.get_result(request.args.get("a", type=int)), db.get_result(request.args.get("b", type=int))
    if not old or not new:
        abort(404)
    if old["meta"]["scan_id"] > new["meta"]["scan_id"]:
        old, new = new, old
    return jsonify(report.compare(old, new))


# --------------------------------------------------------------- devices ---

@app.get("/api/devices")
def api_devices():
    latest = _latest()
    live = {d["ip"]: d for d in (latest["devices"] if latest else [])}
    rows = db.list_devices()
    for r in rows:
        d = live.get(r["ip"]) if r["online"] else None
        r["open_ports"] = d["open_ports"] if d else []
        r["risk_detail"] = d["risk"] if d else None
        r["is_gateway"] = bool(d and d["is_gateway"])
        r["is_self"] = bool(d and d["is_self"])
    return jsonify(rows)


@app.get("/api/devices/<path:key>")
def api_device(key):
    dev = db.get_device(key)
    if not dev:
        abort(404)
    history, current = [], None
    for res in db.recent_results(30):
        match = next((d for d in res["devices"] if (d["mac"] or d["ip"]) == key), None)
        if not match:
            continue
        found = [f for f in res["findings"] if f["ip"] == match["ip"]]
        if current is None:
            current = {"device": match, "findings": found, "scan_id": res["meta"]["scan_id"]}
        history.append({"scan_id": res["meta"]["scan_id"], "finished": res["meta"]["finished"],
                        "ip": match["ip"], "open_ports": [e["port"] for e in match["open_ports"]],
                        "findings": len(found), "risk": match["risk"]["level"]})
    return jsonify({"inventory": dev, "current": current, "history": history})


# -------------------------------------------------------------- findings ---

@app.get("/api/findings/<path:fid>")
def api_finding(fid):
    scan_id = request.args.get("scan", type=int)
    result = db.get_result(scan_id)
    if not result:
        abort(404)
    f = next((f for f in result["findings"] if f["id"] == fid), None)
    if not f:
        abort(404)
    device = next((d for d in result["devices"] if d["ip"] == f["ip"]), None)
    return jsonify({"finding": f, "device": device, "scan": result["meta"]})


# --------------------------------------------------------------- reports ---

@app.get("/api/report")
def api_report():
    fmt = request.args.get("format", "html")
    result = db.get_result(request.args.get("scan", type=int))
    if not result:
        abort(404)
    sections = [s for s in request.args.get("sections", ",".join(report.SECTIONS)).split(",") if s in report.SECTIONS]
    name = f"netguard-scan{result['meta']['scan_id']}-{datetime.now():%Y%m%d-%H%M}"
    if fmt == "html":
        body, mime = report.to_html(result, sections), "text/html"
    elif fmt == "json":
        body, mime = report.to_json(result), "application/json"
    elif fmt == "csv":
        body, mime = report.to_csv(result, sections), "text/csv"
    elif fmt == "pdf":
        try:
            body, mime = report.to_pdf(result, sections), "application/pdf"
        except ImportError:
            return jsonify({"error": "PDF export needs reportlab: pip install reportlab"}), 501
    else:
        abort(404)
    db.audit("Report generated", f"{fmt.upper()} for scan #{result['meta']['scan_id']}")
    disposition = "inline" if request.args.get("inline") else "attachment"
    return Response(body, mimetype=mime,
                    headers={"Content-Disposition": f'{disposition}; filename="{name}.{fmt}"'})


# ------------------------------------------------------- alerts / audit ---

@app.get("/api/alerts")
def api_alerts():
    return jsonify({"alerts": db.list_alerts(), "unread": db.unread_alerts()})


@app.post("/api/alerts/read")
def api_alerts_read():
    db.mark_alerts_read((request.get_json(silent=True) or {}).get("ids"))
    return jsonify({"unread": db.unread_alerts()})


@app.post("/api/alerts/clear")
def api_alerts_clear():
    db.clear_alerts()
    db.audit("Alerts cleared")
    return jsonify({"unread": 0})


@app.get("/api/audit")
def api_audit():
    return jsonify(db.list_audit())


# -------------------------------------------------------------- settings ---

@app.get("/api/settings")
def api_settings():
    return jsonify(db.get_settings())


@app.post("/api/settings")
def api_settings_save():
    values = request.get_json(silent=True) or {}
    values.pop("accepted_terms", None)  # only settable through /api/terms/accept
    try:
        if values.get("authorized_networks"):
            for cidr in values["authorized_networks"].split(","):
                if cidr.strip():
                    network.ipaddress.ip_network(cidr.strip(), strict=False)
        if values.get("custom_ports"):
            ports.parse_ports(values["custom_ports"])
        changed = db.save_settings(values)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": f"Invalid setting: {exc}"}), 400
    db.audit("Settings changed", ", ".join(f"{k}={v}" for k, v in changed.items()))
    return jsonify(db.get_settings())


@app.post("/api/terms/accept")
def api_terms_accept():
    stamp = datetime.now().isoformat(timespec="seconds")
    db.save_settings({"accepted_terms": stamp})
    db.audit("Authorised-use terms accepted", f"by {getpass.getuser()} on {socket.gethostname()}")
    return jsonify({"accepted": stamp})


@app.post("/api/oui/update")
def api_oui_update():
    try:
        status = oui.update_db()
    except Exception as exc:
        return jsonify({"error": f"Download failed: {exc}"}), 502
    db.audit("Vendor database updated", f"{status['entries']} manufacturers")
    return jsonify(status)


def start_background():
    """Shared start-up for the browser server and the desktop app."""
    setup_logging()
    db.audit("Application started", f"v{__version__} on {socket.gethostname()} as {getpass.getuser()}")
    wifi.start_sampler(enabled=lambda: db.get_settings()["wifi_sampling"])
    log.info("NetGuard %s started", __version__)


def serve(port):
    # Bound to localhost on purpose: the dashboard must not be reachable from the LAN.
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    start_background()
    print(f"\n  NetGuard {__version__} dashboard: http://127.0.0.1:{port}\n"
          "  Only scan networks you own or are authorised to test.\n")
    serve(port)
