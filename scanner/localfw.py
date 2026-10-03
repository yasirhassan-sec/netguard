"""Read-only Windows Firewall check for the scanning PC itself.

Scanning your own IP bypasses your own firewall, so an "open" port on this computer may still
be blocked for every other device. This asks Windows which of those ports the firewall would
actually let in on the active network profile. It never changes any setting.
"""
import json

from .utils import IS_WINDOWS, run_cmd

_SCRIPT = r"""
$ports = @(%PORTS%)
$profiles = @(Get-NetConnectionProfile | ForEach-Object { [string]$_.NetworkCategory })
$active = $profiles | ForEach-Object { if ($_ -eq 'DomainAuthenticated') { 'Domain' } else { $_ } }
$procByPort = @{}
foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
  if ($ports -contains [int]$c.LocalPort) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    $procByPort[[int]$c.LocalPort] = if ($c.OwningProcess -eq 4) { 'System' } elseif ($p) { $p.Path } else { '' }
  }
}
# Bulk-load filters once (querying them per rule takes over a minute).
$pf = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $pf[$_.InstanceID] = $_ }
$af = @{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $af[$_.InstanceID] = $_ }
$ad = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $ad[$_.InstanceID] = $_ }
$allowed = @{}
foreach ($r in (Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)) {
  $prof = [string]$r.Profile
  if (-not ($prof -eq 'Any' -or ($active | Where-Object { $prof -match $_ }))) { continue }
  $p = $pf[$r.Name]; $a = $af[$r.Name]
  if (-not $p -or -not $a) { continue }
  if ($a.Package -and $a.Package -ne '*') { continue }   # app-container (Store app) rules only cover that app
  if ($p.Protocol -notin 'TCP', 'Any') { continue }
  $prog = [Environment]::ExpandEnvironmentVariables([string]$a.Program)
  foreach ($port in $ports) {
    $listener = $procByPort[$port]
    $portNamed = $p.LocalPort -contains [string]$port
    $progNamed = $prog -and $prog -ne 'Any' -and $listener -and ($listener -eq $prog -or $listener -like $prog)
    $portAny = ($p.LocalPort -contains 'Any')
    # Count a rule only if it names this port (for any or the matching program),
    # or names the listening program explicitly while allowing any port.
    $match = ($portNamed -and ($prog -eq 'Any' -or $progNamed)) -or ($portAny -and $progNamed)
    # Prefer reporting a rule that names the port explicitly (e.g. "File and Printer Sharing (SMB-In)").
    if ($match -and (-not $allowed.ContainsKey([string]$port) -or ($portNamed -and -not $allowed[[string]$port].named))) {
      $allowed[[string]$port] = @{ rule = $r.DisplayName; remote = (($ad[$r.Name].RemoteAddress) -join ','); named = [bool]$portNamed }
    }
  }
}
@{ profiles = $profiles; allowed = $allowed } | ConvertTo-Json -Depth 4 -Compress
"""


def allowed_inbound(ports):
    """Return {"profiles": [...], "allowed": {port: {"rule", "remote"}}} or None if unknown."""
    if not IS_WINDOWS or not ports:
        return None
    script = _SCRIPT.replace("%PORTS%", ",".join(str(int(p)) for p in ports))
    out, rc = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=90)
    if rc != 0 or not out.strip():
        return None
    try:
        data = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    profiles = data.get("profiles") or []
    return {"profiles": [profiles] if isinstance(profiles, str) else profiles,
            "allowed": {int(k): v for k, v in (data.get("allowed") or {}).items()}}
