"""Scan manager: runs discovery -> ports -> services -> checks -> vulnerability engine,
stores the result and raises alerts by comparing with the previous scan."""
import concurrent.futures as cf
import threading
from datetime import datetime

from . import db, licensing, localfw, network, notify, ports, probes, report, vulns, wifi

SEV_RANK = {s: i for i, s in enumerate(vulns.SEVERITY_ORDER)}


class ScanJob:
    def __init__(self, net, mode, options, site=None):
        self.net = net
        self.mode = mode
        self.options = options
        self.site = site
        self.state = "running"
        self.phase = "Starting"
        self.progress = 0
        self.log = []
        self.error = None
        self.scan_id = None
        self.stats = {"hosts_discovered": 0, "hosts_scanned": 0, "ports_checked": 0,
                      "open_ports": 0, "findings": 0}
        self.started = datetime.now()
        self._lock = threading.Lock()

    def update(self, phase=None, progress=None, msg=None, **stats):
        with self._lock:
            if phase:
                self.phase = phase
            if progress is not None:
                self.progress = max(self.progress, min(100, int(progress)))
            if msg:
                self.log.append(f"[{datetime.now():%H:%M:%S}] {msg}")
            self.stats.update(stats)

    def to_dict(self):
        with self._lock:
            return {"state": self.state, "phase": self.phase, "progress": self.progress,
                    "target": str(self.net), "mode": self.mode, "scan_id": self.scan_id, "site": self.site,
                    "log": self.log[-80:], "error": self.error, "stats": dict(self.stats),
                    "elapsed": round((datetime.now() - self.started).total_seconds())}


def _config_checks(devices, job):
    """SMBv1, legacy TLS, anonymous FTP and SNMP probes. Returns {ip: {...}}."""
    extra = {d["ip"]: {"tls_legacy": {}} for d in devices}
    tasks = []
    for d in devices:
        open_ports = {e["port"]: e for e in d["open_ports"]}
        if 445 in open_ports:
            tasks.append(("smb1", d, 445))
        if 21 in open_ports:
            tasks.append(("ftp_anon", d, 21))
        for p, e in open_ports.items():
            if (e.get("http") or {}).get("tls"):
                tasks.append(("tls", d, p))
        tasks.append(("snmp", d, 161))

    def run(task):
        kind, d, port = task
        if kind == "smb1":
            return probes.smb1_enabled(d["ip"])
        if kind == "ftp_anon":
            return probes.ftp_anonymous(d["ip"])
        if kind == "tls":
            return probes.tls_legacy(d["ip"], port)
        return probes.snmp_public(d["ip"])

    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        for i, (task, res) in enumerate(zip(tasks, pool.map(run, tasks)), 1):
            kind, d, port = task
            if kind == "snmp":
                d["snmp"] = res
            elif kind == "tls":
                if res:
                    extra[d["ip"]]["tls_legacy"][port] = res
            else:
                extra[d["ip"]][kind] = res
            job.update(progress=86 + 6 * i / max(1, len(tasks)))
    return extra


def _alerts(result, previous, first_run, new_keys):
    """Raise alerts by comparing with the previous scan. Returns the alerts created."""
    created = []

    def add(*args):
        created.append(db.add_alert(*args))

    devices = result["devices"]
    if not first_run:
        for d in devices:
            if db.device_key(d) in new_keys:
                add("medium", "new_device", f"New device detected: {d['ip']}",
                    f"{d['vendor']} · {d['hostname'] or 'no hostname'} · MAC {d['mac'] or '-'}")
    if previous:
        old_ids = {f["id"] for f in previous["findings"]}
        for f in result["findings"]:
            if f["id"] not in old_ids and f["severity"] in ("critical", "high"):
                add(f["severity"], "new_vulnerability", f"{f['severity'].title()} vulnerability on {f['host']}",
                    f["title"])
        old_dev = {d["ip"]: d for d in previous["devices"]}
        for d in devices:
            o = old_dev.get(d["ip"])
            if not o:
                continue
            new_ports = {e["port"] for e in d["open_ports"]} - {e["port"] for e in o["open_ports"]}
            for p in sorted(new_ports):
                add("low", "new_service", f"New exposed service: port {p} on {d['ip']}", ports.service_name(p))
            if o.get("risk", {}).get("status") == "secure" and d["risk"]["status"] == "vulnerable":
                add("high", "became_vulnerable", f"{d['ip']} became vulnerable",
                    f"Previously secure; now {d['risk']['level']} risk")
    s = result["summary"]
    add("info", "scan_completed", f"Scan completed: {result['meta']['target']}",
        f"{s['devices']} devices, {len(result['findings'])} findings, score {s['score']}")
    return created


# ------------------------------------------------------------ job control ---

_job = None
_job_lock = threading.Lock()


def current_job():
    return _job


def build_options(settings, overrides=None):
    """Scan options from saved settings, optionally overridden per scan."""
    o = overrides or {}
    return {
        "timeout_ms": min(5000, max(100, settings["timeout_ms"])),
        "threads": min(500, max(10, settings["threads"])),
        "service_detection": o.get("service_detection", settings["service_detection"]),
        "config_checks": o.get("config_checks", settings["config_checks"]),
        "vuln_checks": o.get("vuln_checks", settings["vuln_checks"]),
        "cve_lookup": o.get("cve_lookup", settings["cve_lookup"]),
        "ports": o.get("ports", ""),
    }


def start_job(net, mode, options, site=None, background=True):
    """Start a scan unless one is running. Raises RuntimeError if busy."""
    global _job
    with _job_lock:
        if _job and _job.state == "running":
            raise RuntimeError("A scan is already running")
        _job = ScanJob(net, mode, options, site)
    if background:
        threading.Thread(target=run, args=(_job,), daemon=True, name="scan").start()
    else:
        run(_job)
    return _job


def run_scheduled(mode):
    """Scheduler entry point: scan every saved site (or the default network) one after another."""
    settings = db.get_settings()
    targets = [(s["name"], s["cidr"]) for s in db.list_sites()]
    if not targets:
        default = network.default_target()
        targets = [(None, default)] if default else []
    for site, cidr in targets:
        try:
            net = network.validate_target(cidr, settings["authorized_networks"])
            start_job(net, mode, build_options(settings), site=site, background=False)
        except (ValueError, RuntimeError) as exc:
            db.audit("Scheduled scan skipped", f"{site or cidr}: {exc}")


def run(job):
    opts = job.options
    try:
        job.scan_id = db.create_scan(str(job.net), job.mode, job.site)
        where = f"{job.site} ({job.net})" if job.site else str(job.net)
        db.audit("Scan started", f"#{job.scan_id} {ports.MODES[job.mode]['label']} on {where}")

        wifi_info = {"connected": None, "networks": [], "channels": []}
        if job.mode != "single":
            job.update("Wi-Fi survey", 2, "Reading nearby Wi-Fi networks")
            wifi_info = wifi.survey()
            job.update(msg=f"{len(wifi_info['networks'])} access point(s) visible")

        my_ip = network.local_ip()
        gateway = network.get_gateway()
        hosts = max(1, job.net.num_addresses - 2) if job.net.num_addresses > 2 else job.net.num_addresses
        job.update("Host discovery", 5, f"Discovering hosts in {job.net} ({hosts} address(es))")
        devices = network.discover(job.net, my_ip, progress=lambda f: job.update(progress=5 + f * 30),
                                   include_all=job.mode == "single")
        for d in devices:
            d["is_gateway"] = d["ip"] == gateway
        job.update(msg=f"Found {len(devices)} live device(s)", hosts_discovered=len(devices))

        if job.mode != "single":
            job.update("UPnP discovery", 36, "Listening for UPnP/SSDP announcements")
            upnp = network.ssdp_discover(my_ip)
            for d in devices:
                d["upnp"] = upnp.get(d["ip"], [])
            job.update(msg=f"{len(upnp)} device(s) answered UPnP")

        port_list = ports.ports_for_mode(job.mode, opts.get("ports", ""))
        job.update("Port scan", 40, f"Scanning {len(port_list)} TCP port(s) on {len(devices)} device(s)")
        total = len(port_list) * len(devices)
        checked = ports.scan_devices(
            devices, port_list, timeout=opts["timeout_ms"] / 1000, threads=opts["threads"],
            progress=lambda f: job.update(progress=40 + f * 34, ports_checked=int(f * total),
                                          hosts_scanned=int(f * len(devices))))
        open_count = sum(len(d["open_ports"]) for d in devices)
        job.update(msg=f"{open_count} open port(s) found", ports_checked=checked,
                   hosts_scanned=len(devices), open_ports=open_count)

        if opts["service_detection"]:
            job.update("Service detection", 75, "Identifying services and versions")
            ports.detect_services(devices, progress=lambda f: job.update(progress=75 + f * 10))

        extra = {}
        if opts["config_checks"]:
            job.update("Configuration checks", 86, "Checking SMBv1, TLS versions, anonymous FTP, SNMP")
            extra = _config_checks(devices, job)

        me = next((d for d in devices if d["is_self"] and d["open_ports"]), None)
        if me:
            job.update(msg="Checking Windows Firewall rules for this PC's open ports")
            me["firewall"] = localfw.allowed_inbound([e["port"] for e in me["open_ports"]])

        for d in devices:
            d["os"] = network.guess_os(d)
            d["type"] = network.guess_type(d)

        findings = []
        if opts["vuln_checks"]:
            job.update("Vulnerability assessment", 93, "Running vulnerability engine")
            findings = vulns.analyze(wifi_info, devices, extra, cve=opts["cve_lookup"],
                                     log=lambda m: job.update(msg=m))
        for d in devices:
            d["risk"] = vulns.device_risk(d, findings)
        job.update(msg=f"{len(findings)} finding(s)", findings=len(findings))

        settings = db.get_settings()
        pro = licensing.is_pro(settings)
        result = report.build(str(job.net), job.mode, opts, wifi_info, devices, gateway, findings,
                              job.started, datetime.now())
        result["meta"]["site"] = job.site
        result["meta"]["stats"] = dict(job.stats)
        if pro and settings["brand_company"]:
            result["meta"]["brand"] = {"company": settings["brand_company"], "contact": settings["brand_contact"],
                                       "color": settings["brand_color"]}
        previous = db.previous_result(job.scan_id, str(job.net))
        first_run = not db.known_device_keys()
        before = db.known_device_keys()
        db.finish_scan(job.scan_id, result)
        db.upsert_devices(devices, job.scan_id, result["meta"]["finished"])
        new_keys = {db.device_key(d) for d in devices} - before
        created = _alerts(result, previous, first_run, new_keys)
        db.audit("Scan completed", f"#{job.scan_id}: {len(devices)} hosts, {len(findings)} findings, "
                                   f"score {result['summary']['score']}")
        if pro and (settings["email_enabled"] or settings["telegram_enabled"]):
            job.update("Sending alerts", 99)
            sent = notify.dispatch(created, settings, job.site or str(job.net))
            if sent:
                db.audit("Alerts sent", ", ".join(f"{k}: {v}" for k, v in sent.items()))
        job.update("Completed", 100, f"Scan #{job.scan_id} saved")
        job.state = "done"
    except Exception as exc:
        job.error = f"{type(exc).__name__}: {exc}"
        job.update("Failed", msg=job.error)
        job.state = "error"
        if job.scan_id:
            db.fail_scan(job.scan_id, job.error)
        db.add_alert("high", "scan_failed", f"Scan failed: {job.net}", job.error)
        db.audit("Scan failed", job.error)
