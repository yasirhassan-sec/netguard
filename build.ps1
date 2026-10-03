# NetGuard release build: tests -> licences -> icon -> NetGuard.exe -> installer.
# Usage (from the project root):  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "1/5 Running tests" -ForegroundColor Cyan
python -m pytest -q tests
if ($LASTEXITCODE -ne 0) { throw "Tests failed - fix them before releasing." }

Write-Host "2/5 Collecting third-party licences" -ForegroundColor Cyan
python packaging\collect_licenses.py | Out-Null

Write-Host "3/5 Generating icon" -ForegroundColor Cyan
python packaging\make_icon.py

Write-Host "4/5 Building NetGuard.exe" -ForegroundColor Cyan
pyinstaller packaging\netguard.spec --noconfirm --distpath dist --workpath build --log-level WARN
if (-not (Test-Path dist\NetGuard\NetGuard.exe)) { throw "PyInstaller build failed." }

Write-Host "5/5 Building installer" -ForegroundColor Cyan
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc /Q packaging\installer.iss
    Write-Host "Installer: dist\NetGuard-Setup-*.exe" -ForegroundColor Green
} else {
    Write-Warning "Inno Setup 6 not found - skipped installer. Install it from https://jrsoftware.org/isinfo.php"
}
Write-Host "Done. Portable app: dist\NetGuard\NetGuard.exe" -ForegroundColor Green
