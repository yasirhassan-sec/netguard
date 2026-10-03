"""NetGuard - Home Network Vulnerability Scanner (Flask app + REST API).

Run:  python app.py   then open http://127.0.0.1:5000
Only scan networks you own or have permission to test.
"""
import getpass
import hmac
import logging
import os
import re
import secrets
import socket
from datetime import datetime

from flask import Flask, Response, abort, jsonify, render_template, request

from scanner import (__version__, db, engine, licensing, network, notify, oui, ports, report, scheduler,
                     updates, wifi)
from scanner.paths import RESOURCE_DIR, setup_logging

log = logging.getLogger("netguard")

app = Flask(__name__, template_folder=os.path.join(RESOURCE_DIR, "templates"),
            static_folder=os.path.join(RESOURCE_DIR, "static"))

# Random per-run secret. The page receives it in a <meta> tag and must send it back on every
# state-changing request, so other websites open in the browser can't drive the local API (CSRF).
API_TOKEN = secrets.token_urlsafe(32)
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


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
        "license": licensing.status(db.get_settings()),
        "sites": db.list_sites(),
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
    body = request.get_json(silent=True) or {}
    settings = db.get_settings()
    if not settings["accepted_terms"]:
        return jsonify({"error": "Please confirm the authorised-use terms before scanning."}), 403
    mode = body.get("mode", "quick")
    if mode not in ports.MODES:
        return jsonify({"error": "Unknown scan mode"}), 400
    site = None
    if body.get("site_id"):
        site = next((s for s in db.list_sites() if s["id"] == body["site_id"]), None)
        if not site:
            return jsonify({"error": "Unknown site"}), 400
    target = (site["cidr"] if site else body.get("target") or network.default_target() or "").strip()
    if mode == "single":
        target = target.split("/")[0] + "/32"
    try:
        net = network.validate_target(target, settings["authorized_networks"])
        port_text = body.get("ports") or settings["custom_ports"]
        if mode == "custom":
            ports.parse_ports(port_text)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    overrides = {k: body[k] for k in ("service_detection", "config_checks", "vuln_checks", "cve_lookup") if k in body}
    overrides["ports"] = port_text if mode == "custom" else ""
    try:
        job = engine.start_job(net, mode, engine.build_options(settings, overrides), site["name"] if site else None)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 409
    return jsonify(job.to_dict()), 202


@app.get("/api/scan")
def api_scan_status():
    job = engine.current_job()
    return jsonify(job.to_dict() if job else {"state": "idle"})


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

PRO_SWITCHES = ("schedule_enabled", "email_enabled", "telegram_enabled")
EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


def _pro_required(feature):
    return jsonify({"error": f"{licensing.PRO_FEATURES[feature]} is a NetGuard Pro feature. "
                             "Start the free trial or enter a licence key in Settings.", "pro_required": True}), 402


def _validate_settings(v):
    """Raise ValueError for bad input. Only checks keys that are present."""
    if v.get("authorized_networks"):
        for cidr in v["authorized_networks"].split(","):
            if cidr.strip():
                network.ipaddress.ip_network(cidr.strip(), strict=False)
    if v.get("custom_ports"):
        ports.parse_ports(v["custom_ports"])
    if "schedule_frequency" in v and v["schedule_frequency"] not in ("hourly", "daily", "weekly"):
        raise ValueError("Unknown schedule frequency")
    if "schedule_time" in v and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(v["schedule_time"])):
        raise ValueError("Time must be HH:MM (24-hour)")
    if "schedule_hours" in v and int(v["schedule_hours"]) not in scheduler.HOUR_CHOICES:
        raise ValueError("Every N hours must be one of " + ", ".join(map(str, scheduler.HOUR_CHOICES)))
    if "schedule_weekday" in v and not 0 <= int(v["schedule_weekday"]) <= 6:
        raise ValueError("Unknown weekday")
    if "schedule_mode" in v and v["schedule_mode"] not in ("quick", "full"):
        raise ValueError("Scheduled scans can be Quick or Full")
    if "notify_min_severity" in v and v["notify_min_severity"] not in notify.SEV_RANK:
        raise ValueError("Unknown severity")
    if "smtp_port" in v and not 1 <= int(v["smtp_port"]) <= 65535:
        raise ValueError("SMTP port must be 1-65535")
    for key in ("email_from", "email_to"):
        for addr in str(v.get(key) or "").split(","):
            if addr.strip() and not EMAIL_RE.match(addr.strip()):
                raise ValueError(f"'{addr.strip()}' is not a valid email address")
    token = v.get("telegram_token")
    if token and token != db.SECRET_MASK and not notify.TOKEN_RE.match(token.strip()):
        raise ValueError("The Telegram bot token doesn't look right (get it from @BotFather)")
    if v.get("telegram_chat_id") and not notify.CHAT_RE.match(str(v["telegram_chat_id"]).strip()):
        raise ValueError("The Telegram chat ID should be a number (or @channelname)")
    if v.get("brand_color") and not re.fullmatch(r"#[0-9a-fA-F]{6}", v["brand_color"]):
        raise ValueError("Brand colour must look like #0B7A5E")
    for key in ("brand_company", "brand_contact"):
        if len(str(v.get(key) or "")) > 80:
            raise ValueError("Branding text is limited to 80 characters")


@app.get("/api/settings")
def api_settings():
    return jsonify(db.public_settings())


@app.post("/api/settings")
def api_settings_save():
    values = request.get_json(silent=True) or {}
    for k in db.INTERNAL_KEYS:
        values.pop(k, None)  # licence, trial and terms have their own endpoints
    if not licensing.is_pro(db.get_settings()):
        if any(values.get(k) for k in PRO_SWITCHES):
            feature = "scheduler" if values.get("schedule_enabled") else "notifications"
            return _pro_required(feature)
        if values.get("brand_company") or values.get("brand_contact"):
            return _pro_required("branding")
    try:
        _validate_settings(values)
        changed = db.save_settings(values)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": f"Invalid setting: {exc}"}), 400
    if any(k.startswith("schedule_") for k in changed):
        # Start counting from now so enabling a schedule doesn't fire a scan immediately.
        db.save_settings({"last_scheduled_run": datetime.now().isoformat(timespec="seconds")}, internal=True)
    db.audit("Settings changed", ", ".join(f"{k}={v}" for k, v in changed.items()))
    return jsonify(db.public_settings())


@app.post("/api/terms/accept")
def api_terms_accept():
    stamp = datetime.now().isoformat(timespec="seconds")
    db.save_settings({"accepted_terms": stamp}, internal=True)
    db.audit("Authorised-use terms accepted", f"by {getpass.getuser()} on {socket.gethostname()}")
    return jsonify({"accepted": stamp})


# --------------------------------------------------------------- licence ---

@app.get("/api/license")
def api_license():
    return jsonify(licensing.status(db.get_settings()))


@app.post("/api/license/activate")
def api_license_activate():
    key = str((request.get_json(silent=True) or {}).get("key", "")).strip()
    try:
        payload = licensing.parse_key(key)
    except ValueError as exc:
        db.audit("Licence activation failed", str(exc))
        return jsonify({"error": str(exc)}), 400
    db.save_settings({"license_key": key}, internal=True)
    status = licensing.status(db.get_settings())
    db.audit("Licence activated", f"{payload.get('lic')} for {payload.get('name')}")
    if status["edition"] != "pro":
        return jsonify({**status, "error": status.get("error") or "Licence not active."}), 400
    return jsonify(status)


@app.post("/api/license/remove")
def api_license_remove():
    db.save_settings({"license_key": ""}, internal=True)
    db.audit("Licence removed")
    return jsonify(licensing.status(db.get_settings()))


@app.post("/api/license/trial")
def api_license_trial():
    if db.get_settings()["trial_started"]:
        return jsonify({"error": "The free trial has already been used on this PC."}), 409
    db.save_settings({"trial_started": datetime.now().isoformat(timespec="seconds")}, internal=True)
    db.audit("Pro trial started", f"{licensing.TRIAL_DAYS} days")
    return jsonify(licensing.status(db.get_settings()))


# ----------------------------------------------------------------- sites ---

@app.get("/api/sites")
def api_sites():
    return jsonify(db.list_sites())


@app.post("/api/sites")
def api_sites_add():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    settings = db.get_settings()
    if not name or len(name) > 60:
        return jsonify({"error": "Give the site a name (up to 60 characters)."}), 400
    if not licensing.is_pro(settings) and len(db.list_sites()) >= licensing.FREE_SITE_LIMIT:
        return _pro_required("sites")
    try:
        net = network.validate_target(str(body.get("cidr", "")), settings["authorized_networks"])
        site_id = db.add_site(name, str(net))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "A site with that name already exists."}), 409
    db.audit("Site added", f"{name} ({net})")
    return jsonify({"id": site_id, "sites": db.list_sites()})


@app.delete("/api/sites/<int:site_id>")
def api_sites_delete(site_id):
    db.delete_site(site_id)
    db.audit("Site removed", f"#{site_id}")
    return jsonify(db.list_sites())


# ----------------------------------------------- schedule & notifications ---

@app.get("/api/schedule")
def api_schedule():
    s = db.get_settings()
    nxt = scheduler.next_slot(s, datetime.now()) if licensing.is_pro(s) else None
    return jsonify({"enabled": bool(s["schedule_enabled"]) and licensing.is_pro(s),
                    "next": nxt.isoformat(timespec="minutes") if nxt else None,
                    "frequency": s["schedule_frequency"], "mode": s["schedule_mode"],
                    "last": s["last_scheduled_run"] or None})


@app.post("/api/notify/test")
def api_notify_test():
    s = db.get_settings()
    if not licensing.is_pro(s):
        return _pro_required("notifications")
    channel = (request.get_json(silent=True) or {}).get("channel")
    text = "NetGuard test message: alerts are set up correctly."
    try:
        if channel == "email":
            notify.send_email(s, "NetGuard test alert", text)
        elif channel == "telegram":
            notify.send_telegram(s, text)
        else:
            return jsonify({"error": "Unknown channel"}), 400
    except Exception as exc:
        return jsonify({"error": f"Sending failed: {exc}"}), 502
    db.audit("Test alert sent", channel)
    return jsonify({"sent": channel})


@app.get("/api/update")
def api_update():
    if not db.get_settings()["update_check"]:
        return jsonify({"enabled": False, "current": __version__})
    return jsonify(updates.check(force=bool(request.args.get("force"))))


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
    scheduler.Scheduler(
        get_settings=db.get_settings,
        save_state=lambda ts: db.save_settings({"last_scheduled_run": ts}, internal=True),
        is_pro=licensing.is_pro,
        run_scans=engine.run_scheduled,
    ).start()
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
