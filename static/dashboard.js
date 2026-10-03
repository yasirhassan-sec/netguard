// NetGuard single-page dashboard. Network-sourced text (SSIDs, hostnames, banners) can be
// attacker-controlled, so every value is passed through esc() before it reaches innerHTML.
const $ = (sel) => document.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

let info = null;
let result = null;
let sevFilter = "all";
let pollTimer = null;

// Per-run token the server embeds in the page; required on every state-changing request.
const API_TOKEN = document.querySelector('meta[name="netguard-token"]').content;

async function api(path, opts = {}) {
  if (opts.json !== undefined) {
    opts = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(opts.json) };
  }
  opts.headers = { ...(opts.headers || {}), "X-NetGuard-Token": API_TOKEN };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

const fmtDate = (iso) => iso ? new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "-";
const sevBadge = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
function signalBars(pct) {
  const q = pct >= 80 ? 4 : pct >= 60 ? 3 : pct >= 40 ? 2 : 1;
  return `<span class="signal q${q}" title="${pct}%"><i></i><i></i><i></i><i></i></span>`;
}
function setStatus(state, text) {
  $("#status-pill").className = "pill " + (state || "");
  $("#status-pill").textContent = text;
}

// ------------------------------------------------------------------ setup ---

async function loadInfo() {
  info = await api("/api/info");
  // Flask sorts JSON keys, so put the modes back in a sensible order.
  $("#mode").innerHTML = ["quick", "full", "single", "custom"].filter((k) => info.modes[k])
    .map((k) => `<option value="${k}">${esc(info.modes[k].label)}</option>`).join("");
  $("#target").value = info.default_target || "";
  onModeChange();
  $("#ifaces tbody").innerHTML = info.interfaces.map((i) => `
    <tr class="${i.ip === info.local_ip ? "me" : ""}">
      <td>${esc(i.name)}${i.ip === info.local_ip ? '<span class="tag">active</span>' : ""}</td>
      <td class="mono">${esc(i.ip)}</td><td class="mono">${esc(i.cidr)}</td><td class="mono">${esc(i.mac)}</td>
      <td>${i.up ? (i.speed_mbps ? i.speed_mbps + " Mbps" : "up") : "down"}</td></tr>`).join("");
  renderOui(info.oui);
}

function onModeChange() {
  const mode = $("#mode").value;
  $("#mode-desc").textContent = info.modes[mode].desc;
  $("#ports-field").classList.toggle("hidden", mode !== "custom");
  $("#target-label").textContent = mode === "single" ? "Device IP" : "Target range";
  if (mode === "single" && $("#target").value.includes("/")) $("#target").value = info.gateway || "";
  if (mode !== "single" && !$("#target").value.includes("/")) $("#target").value = info.default_target || "";
}

function renderOui(s) {
  $("#oui-status").textContent = s.installed
    ? `Vendor database loaded (${s.entries.toLocaleString()} manufacturers).`
    : "Manufacturer names need the IEEE vendor database. Click download (one-time, ~3 MB).";
}

// ---------------------------------------------------------------- results ---

function renderResult(r) {
  result = r;
  if (!r) return;
  renderFilters();
  renderFindings();
  renderDevices();
}

// ---------------------------------------------------------------- overview ---

const SEV_COLORS = { critical: "#f0524f", high: "#f28c38", medium: "#e9c440", low: "#4ea3e6", info: "#7d8794", secure: "#3a8f78" };
const scoreColor = (s) => (s >= 80 ? "#2fd3a2" : s >= 60 ? "#e9c440" : s >= 40 ? "#f28c38" : "#f0524f");
const devName = (d) => d.hostname ? d.hostname.split(".")[0]
  : d.is_gateway ? "Router" : d.is_self ? "This computer" : d.type !== "Unknown" ? d.type : "Unknown device";
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

function scoreRing(score, size = 76) {
  const r = size / 2 - 6, c = 2 * Math.PI * r;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="#2a3038" stroke-width="7"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${scoreColor(score)}" stroke-width="7" stroke-linecap="round"
      stroke-dasharray="${(score / 100) * c} ${c}" transform="rotate(-90 ${size / 2} ${size / 2})"/>
    <text x="50%" y="50%" dy="2" text-anchor="middle" fill="#eef1f4" font-size="20" font-weight="700">${score}</text>
    <text x="50%" y="50%" dy="15" text-anchor="middle" fill="#8b949e" font-size="7.5">out of 100</text></svg>`;
}

function headline(score) {
  if (score >= 90) return "Excellent, well protected";
  if (score >= 75) return "Good, a few things to tidy";
  if (score >= 50) return "Fair, needs attention";
  return "At risk, act soon";
}

function renderOverview(r, scans, diff, alerts) {
  if (!r) return;
  const s = r.summary;
  const done = scans.filter((x) => x.status === "completed" && x.summary).reverse(); // oldest first
  const prev = done.length > 1 ? done[done.length - 2] : null;
  const actionable = r.findings.filter((f) => f.severity !== "info");
  const newKeys = new Set((diff?.devices_added || []).map((d) => d.mac || d.ip));

  $("#last-scan").textContent = `${r.meta.target} · Last scan ${fmtDate(r.meta.finished)} · ${r.meta.mode_label} took ${r.meta.duration_s}s`;

  // Score card
  $("#score-ring").innerHTML = scoreRing(s.score);
  $("#score-headline").textContent = headline(s.score);
  const parts = [];
  if (prev) {
    const d = s.score - prev.summary.score;
    parts.push(d === 0 ? "Unchanged since the last scan." : `${d > 0 ? "Up" : "Down"} ${plural(Math.abs(d), "point")} since the last scan.`);
  }
  const urgent = s.counts.critical + s.counts.high;
  if (urgent && s.potential > s.score) {
    parts.push(`Fixing the ${urgent} critical/high finding${urgent === 1 ? "" : "s"} would raise it to about ${s.potential}.`);
  } else if (!urgent) {
    parts.push("No critical or high findings. Keep devices updated.");
  }
  $("#score-text").textContent = parts.join(" ");

  // KPI cards
  $("#k-devices").textContent = s.devices;
  $("#k-devices-sub").innerHTML = newKeys.size ? `<span class="warn">${newKeys.size} new since last scan</span>` : "No new devices";
  $("#k-ports").textContent = s.open_ports;
  const opened = (diff?.port_changes || []).reduce((n, p) => n + p.opened.length, 0);
  $("#k-ports-sub").innerHTML = diff ? (opened ? `<span class="warn">${opened} opened since last scan</span>` : "No new open ports") : "Across all devices";
  $("#k-findings").textContent = actionable.length;
  $("#k-findings-sub").innerHTML = s.counts.critical ? `<span class="bad">${s.counts.critical} critical</span>`
    : s.counts.high ? `<span class="warn">${s.counts.high} high</span>` : `<span class="good">No critical issues</span>`;
  const fixed = (diff?.findings_resolved || []).filter((f) => f.severity !== "info").length;
  const added = (diff?.findings_new || []).filter((f) => f.severity !== "info").length;
  $("#k-fixed").textContent = diff ? fixed : "-";
  $("#k-fixed-sub").innerHTML = diff ? (added ? `<span class="warn">${added} new finding${added === 1 ? "" : "s"}</span>` : `<span class="good">No new findings</span>`)
    : "Needs two scans";

  // Findings by severity + issue types
  const maxSev = Math.max(1, ...SEVERITIES.slice(0, 4).map((k) => s.counts[k]));
  $("#sev-bars").innerHTML = SEVERITIES.slice(0, 4).map((k) => `
    <div class="sev-row"><span class="sev-name ${k}">${k}</span>
      <div class="track"><div class="fill" style="width:${(s.counts[k] / maxSev) * 100}%;background:${SEV_COLORS[k]}"></div></div>
      <b>${s.counts[k]}</b></div>`).join("");
  const cats = Object.entries(s.by_category).filter(([, v]) => v).sort((a, b) => b[1] - a[1]);
  $("#cat-list").innerHTML = cats.length ? cats.map(([k, v]) => `<div class="cat-row"><span>${esc(k)}</span><b>${v}</b></div>`).join("")
    : `<p class="empty">No issues.</p>`;

  $("#net-map").innerHTML = networkMap(r.devices, newKeys);

  // Device summary: riskiest first
  const rank = (d) => SEVERITIES.indexOf(d.risk.level) === -1 ? 9 : SEVERITIES.indexOf(d.risk.level);
  const devs = [...r.devices].sort((a, b) => rank(a) - rank(b) || b.open_ports.length - a.open_ports.length);
  $("#dev-all").textContent = `View all ${r.devices.length}`;
  $("#dev-summary tbody").innerHTML = devs.slice(0, 7).map((d) => `<tr>
    <td><div class="dev-name">${esc(devName(d))}${newKeys.has(d.mac || d.ip) ? ' <span class="new-tag">New</span>' : ""}</div>
      <div class="dev-vendor">${esc(d.vendor)}</div></td>
    <td class="mono">${esc(d.ip)}</td><td>${esc(d.type)}</td>
    <td class="mono">${esc(d.open_ports.map((p) => p.port).join(", ") || "-")}</td>
    <td>${sevBadge(d.risk.level === "secure" ? "secure" : d.risk.level)}</td></tr>`).join("");

  // Top findings
  $("#find-all").textContent = `View all ${actionable.length}`;
  $("#top-findings").innerHTML = actionable.length ? actionable.slice(0, 5).map((f) => `
    <div class="tf">
      <div class="tf-head">${sevBadge(f.severity)}<span class="muted">${esc(f.host)}</span>${f.refs[0] ? `<span class="mono muted">${esc(f.refs[0])}</span>` : ""}</div>
      <div class="tf-title">${esc(f.title)}</div>
      <div class="tf-fix">Fix: ${esc(f.fix)}</div></div>`).join("") : `<p class="empty">Nothing to fix. Nice!</p>`;

  // Score trend
  const last7 = done.slice(-7);
  if (last7.length) {
    $("#score-trend").innerHTML = `<div class="trend">${last7.map((x, i) => {
      const latest = i === last7.length - 1;
      // Scans from the same day are labelled by time, older ones by date.
      const when = new Date(x.finished);
      const sameDay = when.toDateString() === new Date().toDateString();
      const day = latest ? "Latest" : sameDay ? when.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        : when.toLocaleDateString([], { day: "numeric", month: "short" });
      return `<div class="tcol" title="Scan #${x.id}: ${x.summary.score}"><span class="tval">${x.summary.score}</span>
        <div class="tbar ${latest ? "latest" : ""}" style="height:${Math.max(4, x.summary.score)}%"></div><span class="tday">${esc(day)}</span></div>`;
    }).join("")}</div>`;
  }
  $("#trend-note").textContent = diff
    ? `Since last scan: ${fixed} fixed · ${plural(newKeys.size, "new device")} · ${plural(opened, "new port")}` : "";

  // Recent alerts
  $("#recent-alerts").innerHTML = alerts.filter((a) => a.kind !== "scan_completed").slice(0, 4).concat(
    alerts.filter((a) => a.kind === "scan_completed").slice(0, 1)).slice(0, 4).map((a) => `
    <div class="ra"><div><div class="ra-title ${a.severity === "medium" || a.severity === "high" || a.severity === "critical" ? "warn" : ""}">${esc(a.title)}</div>
      <div class="muted">${esc(a.detail)}</div></div><span class="ra-time">${fmtDate(a.ts)}</span></div>`).join("")
    || `<p class="empty">No alerts.</p>`;
}

function networkMap(devices, newKeys) {
  const W = 620, H = 300, cx = W / 2, cy = H / 2 + 6;
  const gw = devices.find((d) => d.is_gateway);
  // Group unremarkable devices of the same type ("Phone / laptop (6)") so the map stays readable.
  const nodes = [], groups = {};
  devices.filter((d) => d !== gw).forEach((d) => {
    const quiet = d.risk.status === "secure" && !newKeys.has(d.mac || d.ip) && !d.is_self;
    if (quiet) (groups[d.type] = groups[d.type] || []).push(d);
    else nodes.push({ label: devName(d), level: d.risk.level, isNew: newKeys.has(d.mac || d.ip), ip: d.ip });
  });
  Object.entries(groups).forEach(([type, list]) => {
    if (list.length === 1) nodes.push({ label: devName(list[0]), level: "secure", ip: list[0].ip });
    else nodes.push({ label: `${type === "Unknown" ? "Other devices" : type} (${list.length})`, level: "secure", ip: list.map((d) => d.ip).join(", ") });
  });
  const n = nodes.length;
  const pts = nodes.map((node, i) => {
    const a = (-90 + (360 / Math.max(n, 1)) * i + (n % 2 ? 0 : 180 / n)) * Math.PI / 180;
    return { ...node, x: cx + 255 * Math.cos(a), y: cy + 112 * Math.sin(a) };
  });
  const color = (lvl) => SEV_COLORS[lvl] || SEV_COLORS.secure;
  const gwColor = gw ? color(gw.risk.level) : "#4ea3e6";
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" class="netmap">
    ${pts.map((p) => `<line x1="${cx}" y1="${cy}" x2="${p.x}" y2="${p.y}" stroke="#39414b" stroke-width="1"/>`).join("")}
    ${pts.map((p) => `<g><title>${esc(p.ip)}</title>
      ${p.isNew ? `<circle cx="${p.x}" cy="${p.y}" r="15" fill="none" stroke="${color(p.level)}" stroke-dasharray="3 3" stroke-width="1.5"/>` : ""}
      <circle cx="${p.x}" cy="${p.y}" r="10" fill="${color(p.level)}"/>
      <text x="${p.x}" y="${p.y + 27}" text-anchor="middle" fill="${p.isNew ? "#f28c38" : "#c9d1d9"}" font-size="11">${esc(p.label.slice(0, 22))}</text></g>`).join("")}
    <circle cx="${cx}" cy="${cy}" r="27" fill="#1d2228" stroke="${gwColor}" stroke-width="2.5"/>
    <path d="M${cx - 9} ${cy + 3}a12 12 0 0 1 18 0M${cx - 5} ${cy + 7}a6 6 0 0 1 10 0" fill="none" stroke="#eef1f4" stroke-width="2" stroke-linecap="round"/>
    <text x="${cx}" y="${cy + 44}" text-anchor="middle" fill="#eef1f4" font-size="11.5" font-weight="600">${gw ? `Router ${esc(gw.ip)}` : "Router"}</text>
  </svg>`;
}

function renderFilters() {
  const counts = result.summary.counts;
  $("#sev-filter").innerHTML = ["all", ...SEVERITIES].map((k) =>
    `<button class="small ${sevFilter === k ? "on" : ""}" data-sev="${k}">${k} ${k === "all" ? result.findings.length : counts[k]}</button>`).join("");
}

function renderFindings() {
  const list = result.findings.filter((f) => sevFilter === "all" || f.severity === sevFilter);
  $("#findings").innerHTML = list.length ? list.map((f) => `
    <div class="finding ${f.severity}">
      <div class="head">${sevBadge(f.severity)}<span class="title">${esc(f.title)}</span><span class="host">${esc(f.host)}</span></div>
      <div class="meta">${esc(f.id)} · ${esc(f.category)} · confidence: ${esc(f.confidence)}${f.port ? ` · port ${f.port}` : ""}${f.service ? ` · ${esc(f.service)}` : ""}${f.version ? ` ${esc(f.version)}` : ""}</div>
      <p>${esc(f.detail)}</p>
      ${f.evidence ? `<div class="evidence">Evidence: ${esc(f.evidence)}</div>` : ""}
      <p class="fix">Fix: ${esc(f.fix)}</p>
      ${f.refs.length ? `<p class="refs">${f.refs.slice(0, 10).map((id) =>
        `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">${esc(id)}</a>`).join(" · ")}</p>` : ""}
    </div>`).join("") : `<p class="empty">${result.findings.length ? "No findings at this severity." : "No issues found. Nice!"}</p>`;
}

let inventory = {};
function renderDevices() {
  const q = $("#dev-search").value.trim().toLowerCase();
  const rows = result.devices.filter((d) => !q || [d.ip, d.hostname, d.vendor, d.os, d.type, d.mac].join(" ").toLowerCase().includes(q));
  $("#devices tbody").innerHTML = rows.length ? rows.map((d) => {
    const inv = inventory[d.mac || d.ip];
    return `<tr class="${d.is_self ? "me" : ""}">
      <td class="mono">${esc(d.ip)}${d.is_gateway ? '<span class="tag">gateway</span>' : ""}${d.is_self ? '<span class="tag">you</span>' : ""}</td>
      <td>${esc(d.hostname) || "-"}</td>
      <td>${esc(d.type)}<span class="banner">${esc(d.os)}</span></td>
      <td>${esc(d.vendor)}</td>
      <td class="mono">${esc(d.mac) || "-"}</td>
      <td><span class="risk-dot ${esc(d.risk.level)}"></span>${esc(d.risk.level)}<span class="banner">${d.risk.findings} finding(s)</span></td>
      <td>${d.open_ports.length ? d.open_ports.map((p) => `
        <span class="chip" title="${esc(p.banner)}">${p.port}/${esc(p.service)}</span>
        ${p.version ? `<span class="banner">${esc(p.version)}</span>` : ""}`).join("") : "-"}
        ${d.upnp.length ? `<span class="banner">UPnP: ${esc(d.upnp[0].server || d.upnp[0].st)}</span>` : ""}</td>
      <td class="banner">${inv ? `first ${fmtDate(inv.first_seen)}` : ""}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">No devices match.</td></tr>`;
}

// ------------------------------------------------------------------ Wi-Fi ---

function renderWifi(w) {
  const c = w.connected;
  $("#wifi-connected").innerHTML = c ? `
    <div class="connected">
      <div><span class="k">Connected to</span><span class="v">${esc(c.ssid)}</span></div>
      <div><span class="k">Signal</span><span class="v">${signalBars(c.signal)}${c.signal}% · ${esc(c.dbm)} dBm</span></div>
      <div><span class="k">Quality</span><span class="v">${esc(c.quality)}</span></div>
      <div><span class="k">Band / channel</span><span class="v">${esc(c.band)} · ch ${esc(c.channel)}</span></div>
      <div><span class="k">Security</span><span class="v">${esc(c.auth)} ${esc(c.encryption)}</span></div>
      <div><span class="k">Risk</span><span class="v">${sevBadge(c.risk.level)} ${esc(c.risk.advice)}</span></div>
      <div><span class="k">Link rate</span><span class="v">${c.rx_mbps ? esc(c.rx_mbps) + " Mbps" : "-"}</span></div>
      <div><span class="k">Router BSSID</span><span class="v mono">${esc(c.bssid)}</span></div>
    </div>` : `<p class="hint">Not connected to Wi-Fi.</p>`;
  $("#wifi-hint").textContent = w.hint || "";

  $("#wifi-table tbody").innerHTML = w.networks.length ? w.networks.map((n) => `
    <tr class="${n.connected ? "me" : ""}">
      <td>${esc(n.ssid)}${n.connected ? '<span class="tag">connected</span>' : ""}<span class="banner mono">${esc(n.bssid)}</span></td>
      <td style="white-space:nowrap">${signalBars(n.signal)}${n.signal}%<span class="banner">${n.dbm} dBm · ${esc(n.quality)}</span></td>
      <td>${esc(n.band)}<span class="banner">ch ${esc(n.channel)}</span></td>
      <td>${esc(n.auth)}<span class="banner">${esc(n.encryption)}</span></td>
      <td>${sevBadge(n.risk.level)}<span class="banner">${esc(n.risk.advice)}</span></td>
    </tr>`).join("") : `<tr><td colspan="5" class="empty">No networks visible.</td></tr>`;

  const max = Math.max(1, ...w.channels.map((x) => x.count));
  $("#channels").innerHTML = w.channels.length ? w.channels.map((ch) => {
    const mine = c && ch.channel === c.channel && ch.band === c.band;
    return `<div class="ch-row ${mine ? "mine" : ""}"><span>${esc(ch.band)} · ${esc(ch.channel)}</span>
      <div class="track"><div class="fill" style="width:${(ch.count / max) * 100}%"></div></div><span>${ch.count}</span></div>`;
  }).join("") : `<p class="empty">No data.</p>`;

  const h = w.history || [];
  if (h.length >= 2) {
    const W = 300, H = 70;
    const pts = h.map((p, i) => `${(i / (h.length - 1)) * W},${H - (p.signal / 100) * H}`).join(" ");
    $("#signal-trend").innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" preserveAspectRatio="none">
      <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2"/></svg>
      <span>${h.length} samples · now ${h[h.length - 1].signal}% · min ${Math.min(...h.map((p) => p.signal))}%</span>`;
  }
}

async function loadWifi() {
  try { renderWifi(await api("/api/wifi")); }
  catch (e) { $("#wifi-hint").textContent = "Wi-Fi survey failed: " + e.message; }
}

// ------------------------------------------------- history, alerts, audit ---

async function loadHistory() {
  const scans = await api("/api/scans");
  const done = scans.filter((s) => s.status === "completed");
  $("#report-scan").innerHTML = done.map((s) =>
    `<option value="${s.id}">#${s.id} · ${fmtDate(s.finished)} · ${esc(s.target)} · ${s.findings} findings</option>`).join("")
    || `<option value="">No completed scans yet</option>`;
  $("#history tbody").innerHTML = scans.map((s) => `<tr>
      <td>${s.status === "completed" ? `<input type="checkbox" class="cmp" value="${s.id}">` : ""}</td>
      <td>#${s.id} ${fmtDate(s.started)}</td><td>${esc(info.modes[s.mode]?.label || s.mode)}</td>
      <td>${s.site ? `<b>${esc(s.site)}</b><br>` : ""}<span class="mono">${esc(s.target)}</span></td><td>${s.devices}</td><td>${s.findings}</td>
      <td>${s.summary ? `${s.summary.score} (${s.summary.grade})` : esc(s.status)}</td><td>${s.duration ? s.duration + "s" : "-"}</td>
    </tr>`).join("") || `<tr><td colspan="8" class="empty">No scans yet.</td></tr>`;
}

async function loadAlerts() {
  const { alerts, unread } = await api("/api/alerts");
  const pill = $("#alert-pill");
  pill.textContent = `Alerts: ${unread}`;
  pill.classList.toggle("unread", unread > 0);
  $("#alert-list").innerHTML = alerts.map((a) => `
    <div class="alert ${a.read ? "" : "unread"}">${sevBadge(a.severity)}
      <div class="body"><div class="title">${esc(a.title)}</div><div class="banner">${esc(a.detail)}</div></div>
      <span class="when">${fmtDate(a.ts)}</span></div>`).join("") || `<p class="empty">No alerts.</p>`;
}

async function loadAudit() {
  const rows = await api("/api/audit");
  $("#audit").innerHTML = rows.map((r) =>
    `<div><span class="t">${fmtDate(r.ts)}</span><b>${esc(r.action)}</b> ${esc(r.detail)}</div>`).join("") || `<p class="empty">Empty.</p>`;
}

async function loadInventory() {
  const devs = await api("/api/devices");
  inventory = Object.fromEntries(devs.map((d) => [d.key, d]));
}

async function compareSelected() {
  const ids = [...document.querySelectorAll(".cmp:checked")].map((c) => c.value);
  if (ids.length !== 2) { $("#compare-result").innerHTML = `<p class="hint">Tick exactly two completed scans.</p>`; return; }
  const d = await api(`/api/compare?a=${ids[0]}&b=${ids[1]}`);
  const li = (items, fn) => items.length ? `<ul>${items.map((x) => `<li>${fn(x)}</li>`).join("")}</ul>` : `<p class="hint">None</p>`;
  $("#compare-result").innerHTML = `<div class="diff">
    <p>Scan #${d.old.id} → #${d.new.id}: score ${d.old.summary.score} → <b>${d.new.summary.score}</b></p>
    <h4 class="bad">New findings (${d.findings_new.length})</h4>${li(d.findings_new, (f) => `${sevBadge(f.severity)} ${esc(f.title)} · ${esc(f.host)}`)}
    <h4 class="good">Resolved findings (${d.findings_resolved.length})</h4>${li(d.findings_resolved, (f) => `${esc(f.title)} · ${esc(f.host)}`)}
    <h4>New devices (${d.devices_added.length})</h4>${li(d.devices_added, (x) => `${esc(x.ip)} ${esc(x.hostname || x.vendor)}`)}
    <h4>Devices gone (${d.devices_removed.length})</h4>${li(d.devices_removed, (x) => `${esc(x.ip)} ${esc(x.hostname || x.vendor)}`)}
    <h4>Port changes (${d.port_changes.length})</h4>${li(d.port_changes, (x) => `${esc(x.ip)}: opened ${esc(x.opened.join(", ") || "-")}, closed ${esc(x.closed.join(", ") || "-")}`)}
  </div>`;
}

// --------------------------------------------------------------- settings ---

// Field: [key, label, type, fullWidth, options]. Types: bool, number, text, password, time, color,
// select (string values) and selectn (numeric values).
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const FORM_GROUPS = {
  settings: { form: "#settings", submit: "Save settings", fields: [
    ["timeout_ms", "Port timeout (ms)", "number"], ["threads", "Threads", "number"],
    ["custom_ports", "Custom scan ports", "text"],
    ["authorized_networks", "Authorized networks (CIDRs, comma-separated; empty = any private)", "text", true],
    ["service_detection", "Service detection", "bool"], ["config_checks", "Configuration checks (SMBv1, TLS, FTP, SNMP)", "bool"],
    ["vuln_checks", "Vulnerability checks", "bool"], ["cve_lookup", "Online CVE lookup by default", "bool"],
    ["wifi_sampling", "Sample Wi-Fi signal in background", "bool"], ["update_check", "Check for NetGuard updates", "bool"],
  ] },
  schedule: { form: "#schedule-form", pro: "scheduler", submit: "Save schedule", fields: [
    ["schedule_enabled", "Run scans automatically", "bool", true],
    ["schedule_frequency", "How often", "select", false, [["daily", "Daily"], ["weekly", "Weekly"], ["hourly", "Every few hours"]]],
    ["schedule_mode", "Scan type", "select", false, [["quick", "Quick scan"], ["full", "Full scan"]]],
    ["schedule_time", "Time (daily or weekly)", "time"],
    ["schedule_weekday", "Day (weekly)", "selectn", false, WEEKDAYS.map((d, i) => [i, d])],
    ["schedule_hours", "Every (hourly)", "selectn", false, [1, 2, 3, 4, 6, 8, 12, 24].map((h) => [h, `${h} hour${h > 1 ? "s" : ""}`])],
  ] },
  notify: { form: "#notify-form", pro: "notifications", submit: "Save alerts", tests: ["email", "telegram"], fields: [
    ["notify_min_severity", "Send alerts for", "select", true,
      [["critical", "Critical only"], ["high", "High and critical"], ["medium", "Medium and above"], ["low", "Low and above"]]],
    ["email_enabled", "Send by email", "bool", true],
    ["smtp_host", "SMTP server", "text"], ["smtp_port", "Port (587 or 465)", "number"],
    ["smtp_user", "Username", "text"], ["smtp_password", "Password", "password"],
    ["email_from", "From", "text"], ["email_to", "To (comma-separated)", "text"],
    ["telegram_enabled", "Send to Telegram", "bool", true],
    ["telegram_token", "Bot token (from @BotFather)", "password"], ["telegram_chat_id", "Chat ID", "text"],
  ] },
  brand: { form: "#brand-form", pro: "branding", submit: "Save branding", fields: [
    ["brand_company", "Company name on reports", "text", true],
    ["brand_contact", "Contact line (email, phone or website)", "text", true],
    ["brand_color", "Report header colour", "color"],
  ] },
};
let license = null;
const isPro = () => license && license.edition === "pro";

function fieldHtml([k, label, type, full, options], s) {
  if (type === "bool") return `<label class="check ${full ? "full" : ""}"><input type="checkbox" name="${k}" ${s[k] ? "checked" : ""}> ${esc(label)}</label>`;
  if (type === "select" || type === "selectn") {
    return `<label class="f ${full ? "full" : ""}">${esc(label)}<select name="${k}">${options.map(([v, t]) =>
      `<option value="${esc(v)}" ${String(s[k]) === String(v) ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></label>`;
  }
  const extra = type === "password" ? ' autocomplete="new-password"' : ' autocomplete="off"';
  return `<label class="f ${full ? "full" : ""}">${esc(label)}<input name="${k}" type="${type}" value="${esc(s[k])}"${extra}></label>`;
}

function renderForm(name, s) {
  const g = FORM_GROUPS[name];
  const locked = g.pro && !isPro();
  $(g.form).innerHTML = `<fieldset ${locked ? "disabled" : ""}>${g.fields.map((f) => fieldHtml(f, s)).join("")}
    <div class="full form-actions"><button class="primary" type="submit">${g.submit}</button>
    ${(g.tests || []).map((c) => `<button type="button" data-test="${c}">Send test ${c === "email" ? "email" : "to Telegram"}</button>`).join("")}
    <span class="hint" data-msg></span></div></fieldset>
    ${locked ? `<p class="hint locked-note">Available in NetGuard Pro. <a href="#pro-sec">Start the free trial</a> to try it.</p>` : ""}`;
}

async function loadSettings() {
  const s = await api("/api/settings");
  $("#cve").checked = s.cve_lookup;
  Object.keys(FORM_GROUPS).forEach((name) => renderForm(name, s));
}

async function saveForm(name, form) {
  const values = {};
  FORM_GROUPS[name].fields.forEach(([k, , type]) => {
    const el = form.elements[k];
    values[k] = type === "bool" ? el.checked : (type === "number" || type === "selectn") ? Number(el.value) : el.value;
  });
  const msg = form.querySelector("[data-msg]");
  try {
    await api("/api/settings", { json: values });
    msg.textContent = "Saved.";
    loadAudit();
    if (name === "schedule") loadSchedule();
  } catch (err) { msg.textContent = err.message; }
}

// ------------------------------------------------------- licence & sites ---

function renderLicense(st) {
  license = st;
  const pill = $("#edition-pill"), badge = $("#license-badge");
  const label = st.edition !== "pro" ? "Free" : st.source === "trial" ? `Pro trial · ${st.days_left} day${st.days_left === 1 ? "" : "s"} left` : "Pro";
  [pill, badge].forEach((el) => { el.textContent = label; el.className = `pill ${st.edition === "pro" ? "done" : ""}`; });
  document.querySelectorAll("[data-pro]").forEach((t) => t.classList.toggle("unlocked", st.edition === "pro"));
  const lic = st.license;
  let html = "";
  if (st.source === "license") {
    html = `<p><b>Licensed to ${esc(lic.name)}</b> (${esc(lic.email)})</p>
      <p class="hint">Licence ${esc(lic.id)} · ${lic.exp ? `valid until ${esc(lic.exp)}` : "does not expire"} · ${esc(lic.seats)} seat(s)</p>
      <button type="button" id="license-remove">Remove licence</button>`;
  } else {
    if (st.source === "trial") html += `<p><b>Pro trial active:</b> ${st.days_left} day${st.days_left === 1 ? "" : "s"} left.</p>`;
    else html += `<p>You're using <b>NetGuard Free</b>. Pro adds:</p>`;
    if (st.source !== "trial") html += `<ul class="feature-list">${Object.values(st.features).map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`;
    if (st.trial_available) html += `<button type="button" class="primary" id="trial-start">Start ${st.trial_days}-day free trial</button>`;
    else if (st.source === "trial_ended") html += `<p class="hint">Your free trial has ended.</p>`;
    html += `<form id="license-form" class="key-form"><textarea name="key" rows="3" placeholder="Paste your licence key (NG1-...)" spellcheck="false"></textarea>
      <button type="submit">Activate licence</button></form>`;
  }
  if (st.error) html += `<p class="note error">${esc(st.error)}</p>`;
  $("#license-body").innerHTML = html;
}

async function loadLicense() {
  renderLicense(await api("/api/license"));
}

function renderSites(sites) {
  $("#sites-list").innerHTML = sites.length ? sites.map((s) => `
    <div class="site-row"><div><b>${esc(s.name)}</b> <span class="mono muted">${esc(s.cidr)}</span></div>
    <button type="button" class="small" data-del-site="${s.id}">Remove</button></div>`).join("")
    : `<p class="hint">No saved sites yet.</p>`;
  const sel = $("#site"), current = sel.value;
  sel.innerHTML = `<option value="">This network</option>` +
    sites.map((s) => `<option value="${s.id}">${esc(s.name)} (${esc(s.cidr)})</option>`).join("");
  sel.value = sites.some((s) => String(s.id) === current) ? current : "";
  onSiteChange();
}

async function loadSites() {
  renderSites(await api("/api/sites"));
}

function onSiteChange() {
  const siteId = $("#site").value;
  const site = [...$("#site").options].find((o) => o.value === siteId && siteId);
  $("#target").disabled = !!site;
  if (site) $("#target").value = site.textContent.match(/\(([^)]+)\)$/)?.[1] || "";
  else if (info && !$("#target").value) $("#target").value = info.default_target || "";
}

async function loadSchedule() {
  const sc = await api("/api/schedule");
  const when = sc.next ? new Date(sc.next).toLocaleString([], { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : null;
  $("#next-scan").classList.toggle("hidden", !(sc.enabled && when));
  $("#next-scan").textContent = when ? `Next scheduled scan: ${when} · ${sc.mode === "full" ? "Full" : "Quick"} scan` : "";
  $("#schedule-next").textContent = sc.enabled && when
    ? `Next run: ${when}. NetGuard must be running (enable "Start with Windows" in the installer).`
    : "Scheduled scans are off.";
}

async function loadUpdate() {
  try {
    const u = await api("/api/update");
    if (u.available && u.url) {
      const b = $("#update-banner");
      b.innerHTML = `NetGuard ${esc(u.latest)} is available (you have ${esc(u.current)}). ${esc(u.notes || "")}
        <a href="${esc(u.url)}" target="_blank" rel="noopener">Download</a>`;
      b.classList.remove("hidden");
    }
  } catch (e) { /* offline: ignore */ }
}

// ------------------------------------------------------------------- scan ---

function renderJob(job) {
  if (job.state === "idle") return;
  $("#progress-card").classList.remove("hidden");
  $("#phase").textContent = job.phase + (job.state === "running" ? "..." : "");
  $("#pct").textContent = job.progress + "%";
  $("#bar-fill").style.width = job.progress + "%";
  const st = job.stats || {};
  $("#job-stats").innerHTML = [["Hosts discovered", st.hosts_discovered], ["Hosts scanned", st.hosts_scanned],
    ["Ports checked", st.ports_checked], ["Open ports", st.open_ports], ["Findings", st.findings], ["Elapsed", `${job.elapsed}s`]]
    .map(([k, v]) => `<span>${k}: <b>${esc(v ?? 0)}</b></span>`).join("");
  const log = $("#log");
  log.textContent = job.log.join("\n");
  log.scrollTop = log.scrollHeight;

  const running = job.state === "running";
  $("#start").disabled = running;
  if (running) setStatus("running", `Scanning ${job.target}`);
  else if (job.state === "done") setStatus("done", "Scan complete");
  else if (job.state === "error") setStatus("error", "Scan failed");

  if (!running && pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
    refreshAll();
  }
}

async function poll() {
  try { renderJob(await api("/api/scan")); } catch (e) { /* server restarting */ }
}

async function startScan() {
  $("#start-error").textContent = "";
  try {
    const mode = $("#mode").value;
    const siteId = mode !== "single" && $("#site").value ? Number($("#site").value) : null;
    const job = await api("/api/scan", { json: {
      mode, target: $("#target").value, ports: $("#ports").value, cve_lookup: $("#cve").checked,
      ...(siteId ? { site_id: siteId } : {}),
    } });
    renderJob(job);
    if (!pollTimer) pollTimer = setInterval(poll, 1000);
  } catch (e) {
    $("#start-error").textContent = e.message;
  }
}

async function refreshAll() {
  await loadInventory().catch(() => {});
  const [o, scans] = await Promise.all([api("/api/overview"), api("/api/scans")]);
  renderResult(o.result);
  // Compare and chart only scans of the same network as the latest one (a single-device scan
  // would otherwise make every other device look "new").
  const target = o.result?.meta.target;
  const same = scans.filter((s) => s.status === "completed" && s.target === target);
  let diff = null;
  if (o.result && same.length > 1) diff = await api(`/api/compare?a=${same[1].id}&b=${same[0].id}`).catch(() => null);
  renderOverview(o.result, same, diff, o.alerts);
  loadSchedule().catch(() => {});
  loadHistory();
  loadAlerts();
  loadAudit();
}

// ------------------------------------------------------------------ wiring ---

$("#mode").addEventListener("change", onModeChange);
$("#start").addEventListener("click", startScan);
$("#wifi-refresh").addEventListener("click", loadWifi);
$("#dev-search").addEventListener("input", () => result && renderDevices());
$("#sev-filter").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-sev]");
  if (!b) return;
  sevFilter = b.dataset.sev;
  renderFilters();
  renderFindings();
});
document.querySelectorAll(".report-row a[data-fmt]").forEach((a) => a.addEventListener("click", (e) => {
  e.preventDefault();
  const id = $("#report-scan").value;
  if (!id) return;
  const inline = a.dataset.fmt === "html" ? "&inline=1" : "";
  window.open(`/api/report?scan=${id}&format=${a.dataset.fmt}${inline}`, "_blank");
  setTimeout(loadAudit, 1000);
}));
$("#compare").addEventListener("click", compareSelected);

function showTerms() {
  const modal = $("#terms-modal");
  modal.classList.remove("hidden");
  $("#terms-check").addEventListener("change", (e) => { $("#terms-accept").disabled = !e.target.checked; });
  $("#terms-accept").addEventListener("click", async () => {
    try {
      await api("/api/terms/accept", { json: {} });
      info.terms_accepted = true;
      modal.classList.add("hidden");
      loadAudit();
    } catch (err) { alert(err.message); }
  });
}

// Highlight the menu link of the section currently on screen.
const navLinks = [...document.querySelectorAll("#section-nav a")];
const observer = new IntersectionObserver((entries) => {
  entries.forEach((en) => {
    if (!en.isIntersecting) return;
    navLinks.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + en.target.id));
  });
}, { rootMargin: "-45% 0px -50% 0px" });
navLinks.forEach((a) => { const sec = document.querySelector(a.getAttribute("href")); if (sec) observer.observe(sec); });
$("#alerts-read").addEventListener("click", async () => { await api("/api/alerts/read", { json: {} }); loadAlerts(); });
Object.entries(FORM_GROUPS).forEach(([name, g]) => {
  const form = $(g.form);
  form.addEventListener("submit", (e) => { e.preventDefault(); saveForm(name, form); });
  form.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-test]");
    if (!b) return;
    const msg = form.querySelector("[data-msg]");
    msg.textContent = "Sending... (save first if you changed anything)";
    try { await api("/api/notify/test", { json: { channel: b.dataset.test } }); msg.textContent = "Test sent."; }
    catch (err) { msg.textContent = err.message; }
  });
});

$("#license-body").addEventListener("click", async (e) => {
  const act = e.target.id === "trial-start" ? "/api/license/trial" : e.target.id === "license-remove" ? "/api/license/remove" : null;
  if (!act) return;
  try { renderLicense(await api(act, { json: {} })); loadSettings(); loadSchedule(); loadAudit(); }
  catch (err) { alert(err.message); }
});
$("#license-body").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    renderLicense(await api("/api/license/activate", { json: { key: e.target.elements.key.value } }));
    loadSettings(); loadSchedule(); loadAudit();
  } catch (err) {
    await loadLicense();
    $("#license-body").insertAdjacentHTML("beforeend", `<p class="note error">${esc(err.message)}</p>`);
  }
});

$("#site").addEventListener("change", onSiteChange);
$("#site-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#site-error").textContent = "";
  try {
    const r = await api("/api/sites", { json: { name: e.target.elements.name.value, cidr: e.target.elements.cidr.value } });
    e.target.reset();
    renderSites(r.sites);
    loadAudit();
  } catch (err) { $("#site-error").textContent = err.message; }
});
$("#sites-list").addEventListener("click", async (e) => {
  const id = e.target.dataset.delSite;
  if (!id) return;
  renderSites(await api(`/api/sites/${id}`, { method: "DELETE" }));
  loadAudit();
});
$("#oui-update").addEventListener("click", async (ev) => {
  ev.target.disabled = true;
  $("#oui-status").textContent = "Downloading vendor database...";
  try { renderOui(await api("/api/oui/update", { method: "POST" })); }
  catch (e) { $("#oui-status").textContent = e.message; }
  ev.target.disabled = false;
});

(async () => {
  try {
    await loadInfo();
  } catch (e) {
    setStatus("error", "Server unreachable");
    return;
  }
  if (!info.terms_accepted) showTerms();
  renderLicense(info.license);
  renderSites(info.sites);
  loadWifi();
  loadSettings();
  loadSchedule();
  loadUpdate();
  await refreshAll();
  const job = await api("/api/scan").catch(() => ({ state: "idle" }));
  renderJob(job);
  if (job.state === "running") pollTimer = setInterval(poll, 1000);
  setInterval(loadWifi, 30000);
})();
