# NetGuard - Home Network Vulnerability Scanner

NetGuard is a Windows desktop app that audits a home or small-office network. It covers Wi-Fi security, devices, open services and known weaknesses, and every finding explains why it matters and how to fix it.

> **Authorised use only.** NetGuard refuses public IP ranges, limits each scan to a /22 or smaller, and asks the user to confirm on first run that they own or are authorised to test the network.

## How to run

Open a terminal in the project folder (`D:\cybersecurity`). In VS Code use **Terminal > New Terminal**.

### Install the requirements (once)

```bash
pip install -r requirements.txt
```
To also run the tests and build releases, install the developer tools:
```bash
pip install -r requirements-dev.txt
```

### Option 1: in your browser (best while developing)

1. If an old NetGuard server is still running, stop it with `Ctrl+C` in its terminal.
2. Start it:
   ```bash
   python app.py
   ```
3. Open **http://127.0.0.1:5000** and press **Ctrl+F5** so the browser doesn't show an old cached page.

### Option 2: desktop window (how customers see it)

```bash
python desktop.py
```
NetGuard opens in its own window. Closing the window stops it.

### Option 3: standalone program (no Python needed)

Build it first, and rebuild it after every change:
```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```
Then run:
```bash
dist\NetGuard\NetGuard.exe
```
The build script runs the tests, collects the third-party licences, builds `dist\NetGuard\NetGuard.exe`, and builds `dist\NetGuard-Setup-<ver>.exe` if [Inno Setup 6](https://jrsoftware.org/isinfo.php) is installed.

### First time it opens

1. A **Before your first scan** screen appears. Tick the box and click **Accept and continue**.
2. Choose **Quick Scan**, check the target (for example `192.168.1.0/24`) and click **Start scan**. It takes about 30 seconds.
3. The overview, network map, findings and devices fill in when it finishes.

### Troubleshooting

- **The Wi-Fi list is empty:** turn on Location services (Settings > Privacy & security > Location).
- **"Address already in use":** another NetGuard is still running. Stop it, or start this one on another port (PowerShell):
  ```bash
  $env:PORT=5002; python app.py
  ```
- **The page looks old or broken after an update:** restart the server, then press **Ctrl+F5** in the browser.

## Test

Check that everything still works:
```bash
python -m pytest -q tests
```

## Features

- **Wi-Fi survey:** signal (% and dBm), band and channel, security type, risk per network, channel congestion and a signal trend.
- **Discovery:** ping and ARP sweep, MAC vendor (IEEE OUI), hostname, OS guess and device type. Devices are tracked over time (first and last seen).
- **Scan modes:** Quick (~50 ports), Full (1-1024 plus common ports), Single Device, Custom ports.
- **Service detection:** banners, HTTP status, title and headers, and TLS version.
- **Checks:** none of them exploit anything.
  - Telnet, ADB, VNC, RDP, SMB, exposed databases, the Docker API
  - SMBv1, legacy TLS, anonymous FTP, SNMP `public`, unauthenticated Redis
  - Missing HTTP security headers, login pages over plain HTTP, router UPnP and HTTP-only admin
  - Known-bad versions such as vsftpd 2.3.4 and OpenSSH (regreSSHion)
  - Optional NVD CVE lookup
- **This-PC firewall awareness:** checks the Windows Firewall rules (read-only) to tell real exposure apart from blocked ports.
- **Risk:** per-device risk plus a network score (NetGuard's own heuristic, weighted by detection confidence).
- **History:** scan comparison, alerts (new device, new vulnerability, new port, a device that became vulnerable) and an audit log.
- **Reports:** PDF, HTML, CSV and JSON, with selectable sections.

## Security of the app itself

- The server listens on `127.0.0.1` only.
- The Host header is checked, which blocks DNS rebinding.
- Every state-changing request needs a per-run token, which blocks CSRF from other websites.
- Security headers are set on responses: CSP, X-Frame-Options, nosniff and no-referrer.
- Network-sourced text (SSIDs, banners) is escaped before display.

## Data locations

- **Development:** `./data`
- **Installed:** `%LOCALAPPDATA%\NetGuard`. Override it with the `NETGUARD_HOME` environment variable. The database, logs (`logs\netguard.log`, rotating) and the vendor database all live here.

## Project layout

```
app.py              Flask app, REST API, security middleware
desktop.py          Native desktop window (pywebview) + single-instance lock
scanner/            Engine: wifi, network, ports, probes, localfw, vulns, engine, report, db, oui, paths
templates/, static/ Dashboard (index.html, dashboard.js/.css) and the HTML report template
tests/              pytest suite (engine rules, parsers, API security)
packaging/          PyInstaller spec, Inno Setup script, icon and licence tools
legal/              EULA and privacy policy DRAFTS (lawyer review required before sale)
LICENSES/           Third-party notices (generated)
```

## Roadmap to commercial release

1. ~~Foundation: app security, data paths, logging, tests~~ (done)
2. ~~Desktop app + installer~~ (done; installer needs Inno Setup)
3. **Editions and licensing:** Free vs Pro, offline-verifiable signed licence keys, trial
4. **Pro features:** scheduled scans, multiple sites, branded reports, notifications, user accounts
5. **Release readiness:** code-signing certificate, final EULA and privacy policy, update checker, website and payments
