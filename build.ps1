# NetGuard release build: tests -> licences -> icon -> NetGuard.exe -> (sign) -> installer -> (sign).
# Usage (from the project root):  powershell -ExecutionPolicy Bypass -File build.ps1
#
# Code signing (optional, recommended for sale): set these before building
#   $env:NETGUARD_SIGN_CERT = "C:\path\to\codesign.pfx"
#   $env:NETGUARD_SIGN_PASS = "<pfx password>"
# signtool.exe comes with the Windows SDK. For EV / cloud (HSM) certificates, replace the
# Sign-File function with your provider's signing command.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Sign-File($path) {
    if (-not $env:NETGUARD_SIGN_CERT) { return }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found - install the Windows SDK." }
    & $signtool.FullName sign /f $env:NETGUARD_SIGN_CERT /p $env:NETGUARD_SIGN_PASS /fd sha256 `
        /tr http://timestamp.digicert.com /td sha256 /d "NetGuard" $path
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $path" }
    Write-Host "  signed $path" -ForegroundColor Green
}

Write-Host "1/6 Running tests" -ForegroundColor Cyan
python -m pytest -q tests
if ($LASTEXITCODE -ne 0) { throw "Tests failed - fix them before releasing." }

Write-Host "2/6 Collecting third-party licences" -ForegroundColor Cyan
python packaging\collect_licenses.py | Out-Null

Write-Host "3/6 Generating icon" -ForegroundColor Cyan
python packaging\make_icon.py

Write-Host "4/6 Building NetGuard.exe" -ForegroundColor Cyan
pyinstaller packaging\netguard.spec --noconfirm --distpath dist --workpath build --log-level WARN
if (-not (Test-Path dist\NetGuard\NetGuard.exe)) { throw "PyInstaller build failed." }
if (Get-ChildItem dist\NetGuard -Recurse -Filter "*DarkGarden*") { throw "GPL DarkGarden font found in the build." }

Write-Host "5/6 Code signing" -ForegroundColor Cyan
if ($env:NETGUARD_SIGN_CERT) { Sign-File "dist\NetGuard\NetGuard.exe" }
else { Write-Warning "NETGUARD_SIGN_CERT not set - NetGuard.exe is UNSIGNED (Windows will warn users)." }

Write-Host "6/6 Building installer" -ForegroundColor Cyan
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc /Q packaging\installer.iss
    $setup = Get-ChildItem dist\NetGuard-Setup-*.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Sign-File $setup.FullName
    Write-Host "Installer: $($setup.FullName)" -ForegroundColor Green
} else {
    Write-Warning "Inno Setup 6 not found - skipped installer. Install it from https://jrsoftware.org/isinfo.php"
}
Write-Host "Done. Portable app: dist\NetGuard\NetGuard.exe" -ForegroundColor Green
