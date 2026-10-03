"""Result assembly, scan comparison and report export (HTML / PDF / CSV / JSON)."""
import csv
import io
import json
import os
import platform
import socket

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import ports, vulns
from .paths import RESOURCE_DIR

TEMPLATE_DIR = os.path.join(RESOURCE_DIR, "templates")
_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=select_autoescape(["html"]))

SECTIONS = ["summary", "network", "devices", "vuln_summary", "critical", "findings", "remediation", "config"]


def build(target, mode, options, wifi, devices, gateway, findings, started, finished):
    vulnerable = sum(1 for d in devices if d["risk"]["status"] == "vulnerable")
    return {
        "meta": {
            "target": target,
            "mode": mode,
            "mode_label": ports.MODES[mode]["label"],
            "options": {k: options[k] for k in ("timeout_ms", "threads", "service_detection",
                                                 "config_checks", "vuln_checks", "cve_lookup") if k in options},
            "ports": options.get("ports", ""),
            "gateway": gateway,
            "scanner_host": socket.gethostname(),
            "platform": platform.platform(),
            "started": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - started).total_seconds(), 1),
        },
        "summary": dict(vulns.score(findings),
                        devices=len(devices),
                        vulnerable_devices=vulnerable,
                        affected_devices=sum(1 for d in devices if d["risk"]["findings"]),
                        open_ports=sum(len(d["open_ports"]) for d in devices),
                        wifi_networks=len(wifi.get("networks", []))),
        "wifi": wifi,
        "devices": devices,
        "findings": findings,
    }


def compare(old, new):
    """Diff two scan results: devices added/removed, findings new/resolved, port changes."""
    od = {d["mac"] or d["ip"]: d for d in old["devices"]}
    nd = {d["mac"] or d["ip"]: d for d in new["devices"]}
    of = {f["id"]: f for f in old["findings"]}
    nf = {f["id"]: f for f in new["findings"]}
    port_changes = []
    for key in od.keys() & nd.keys():
        before = {e["port"] for e in od[key]["open_ports"]}
        after = {e["port"] for e in nd[key]["open_ports"]}
        if before != after:
            port_changes.append({"ip": nd[key]["ip"], "opened": sorted(after - before), "closed": sorted(before - after)})
    return {
        "old": {"id": old["meta"].get("scan_id"), "finished": old["meta"]["finished"], "summary": old["summary"]},
        "new": {"id": new["meta"].get("scan_id"), "finished": new["meta"]["finished"], "summary": new["summary"]},
        "devices_added": [nd[k] for k in nd.keys() - od.keys()],
        "devices_removed": [od[k] for k in od.keys() - nd.keys()],
        "findings_new": [nf[k] for k in nf.keys() - of.keys()],
        "findings_resolved": [of[k] for k in of.keys() - nf.keys()],
        "port_changes": port_changes,
    }


def remediation_plan(findings):
    """Group fixes by action so the report has a short prioritized to-do list."""
    plan = {}
    for f in findings:
        if f["severity"] == "info":
            continue
        item = plan.setdefault(f["fix"], {"fix": f["fix"], "severity": f["severity"], "hosts": set(), "titles": set()})
        item["hosts"].add(f["host"])
        item["titles"].add(f["title"])
        if vulns.SEVERITY_ORDER.index(f["severity"]) < vulns.SEVERITY_ORDER.index(item["severity"]):
            item["severity"] = f["severity"]
    out = sorted(plan.values(), key=lambda p: vulns.SEVERITY_ORDER.index(p["severity"]))
    return [dict(p, hosts=sorted(p["hosts"]), titles=sorted(p["titles"])) for p in out]


def to_html(result, sections=SECTIONS):
    return _env.get_template("report.html").render(r=result, s=set(sections),
                                                    plan=remediation_plan(result["findings"]))


def to_json(result):
    return json.dumps(result, indent=2)


def to_csv(result, sections=SECTIONS):
    buf = io.StringIO()
    w = csv.writer(buf)
    if "findings" in sections or "critical" in sections or "vuln_summary" in sections:
        w.writerow(["Finding ID", "Severity", "Confidence", "Category", "Host", "IP", "Port", "Service",
                    "Version", "Title", "Why it matters", "Evidence", "Recommended fix", "References"])
        for f in result["findings"]:
            w.writerow([f["id"], f["severity"], f["confidence"], f["category"], f["host"], f["ip"] or "",
                        f["port"] or "", f["service"], f["version"], f["title"], f["detail"], f["evidence"],
                        f["fix"], " ".join(f["refs"])])
        w.writerow([])
    if "devices" in sections or "network" in sections:
        w.writerow(["IP", "Hostname", "MAC", "Vendor", "Type", "OS", "Risk", "Open ports"])
        for d in result["devices"]:
            w.writerow([d["ip"], d["hostname"], d["mac"] or "", d["vendor"], d["type"], d["os"],
                        d["risk"]["level"], " ".join(f"{e['port']}/{e['service']}" for e in d["open_ports"])])
    return buf.getvalue()


def to_pdf(result, sections=SECTIONS):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    sev_color = {"critical": "#cf222e", "high": "#d1590b", "medium": "#9a6700", "low": "#0969da", "info": "#6e7781"}
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#57606a"))
    h1, h2 = ss["Title"], ss["Heading2"]
    P = lambda t, st=body: Paragraph(escape(str(t)), st)

    def table(rows, widths):
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1d36")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d7de")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ]))
        return t

    m, s, findings = result["meta"], result["summary"], result["findings"]
    story = [Paragraph("NetGuard - Network Security Report", h1),
             P(f"Target {m['target']} · {m['mode_label']} · {m['finished']} · scanned from {m['scanner_host']}", small),
             Spacer(1, 6 * mm)]
    if "summary" in sections:
        story += [Paragraph("1. Executive summary", h2),
                  P(f"NetGuard score {s['score']}/100 (grade {s['grade']}, {s['status']}). "
                    f"{s['devices']} devices found, {s['vulnerable_devices']} with critical/high issues, "
                    f"{len(findings)} findings: " + ", ".join(f"{v} {k}" for k, v in s["counts"].items() if v) + ". "
                    "The score is NetGuard's own heuristic, not an industry-standard rating.")]
    if "network" in sections and result["wifi"].get("connected"):
        c = result["wifi"]["connected"]
        story += [Paragraph("2. Network overview", h2),
                  P(f"Wi-Fi '{c['ssid']}' ({c['auth']}/{c['encryption']}), {c['band']} channel {c['channel']}, "
                    f"signal {c['signal']}% ({c['dbm']} dBm). Gateway {m['gateway']}. "
                    f"{s['wifi_networks']} access points visible.")]
    if "devices" in sections:
        rows = [["IP", "Hostname", "Vendor", "Type / OS", "Risk", "Open ports"]]
        for d in result["devices"]:
            rows.append([P(d["ip"]), P(d["hostname"] or "-"), P(d["vendor"]), P(f"{d['type']} / {d['os']}"),
                         P(d["risk"]["level"]), P(", ".join(str(e["port"]) for e in d["open_ports"]) or "-")])
        story += [Paragraph("3. Discovered devices", h2), table(rows, [24*mm, 30*mm, 34*mm, 38*mm, 16*mm, 38*mm])]
    if "vuln_summary" in sections:
        rows = [["Severity", "Count"]] + [[k.title(), v] for k, v in s["counts"].items()]
        rows2 = [["Category", "Count"]] + [[k, v] for k, v in s["by_category"].items() if v]
        story += [Paragraph("4. Vulnerability summary", h2), table(rows, [40*mm, 20*mm]), Spacer(1, 3*mm),
                  table(rows2, [40*mm, 20*mm])]
    if "critical" in sections:
        crit = [f for f in findings if f["severity"] in ("critical", "high")]
        story.append(Paragraph("5. Critical findings", h2))
        story += [P(f"[{f['severity'].upper()}] {f['title']} - {f['host']}") for f in crit] or [P("None.")]
    if "findings" in sections:
        story.append(Paragraph("6. Detailed findings", h2))
        for f in findings:
            story += [Paragraph(f"<font color='{sev_color[f['severity']]}'><b>{f['severity'].upper()}</b></font> "
                                f"<b>{escape(f['title'])}</b>", body),
                      P(f"{f['id']} · {f['host']}" + (f" · port {f['port']}" if f["port"] else "")
                        + f" · confidence {f['confidence']}", small),
                      P(f["detail"]), P("Evidence: " + (f["evidence"] or "-"), small),
                      P("Fix: " + f["fix"]), Spacer(1, 3 * mm)]
    if "remediation" in sections:
        story.append(Paragraph("7. Recommended remediation", h2))
        for i, p in enumerate(remediation_plan(findings), 1):
            story.append(P(f"{i}. [{p['severity'].upper()}] {p['fix']} ({', '.join(p['hosts'])})"))
    if "config" in sections:
        o = m["options"]
        story += [Paragraph("8. Scan configuration", h2),
                  P(f"Mode {m['mode_label']}; target {m['target']}; timeout {o.get('timeout_ms')} ms; "
                    f"threads {o.get('threads')}; service detection {o.get('service_detection')}; "
                    f"configuration checks {o.get('config_checks')}; CVE lookup {o.get('cve_lookup')}."),
                  Paragraph("9. Scan timestamp", h2),
                  P(f"Started {m['started']}, finished {m['finished']} ({m['duration_s']} s) on {m['platform']}.")]

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=14*mm, rightMargin=14*mm, topMargin=14*mm,
                      bottomMargin=14*mm, title="NetGuard report").build(story)
    return buf.getvalue()
