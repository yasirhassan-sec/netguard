# PyInstaller spec for the NetGuard desktop app.
# Build:  pyinstaller packaging/netguard.spec --noconfirm   (run from the project root)
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(ROOT, "desktop.py")],
    pathex=[ROOT],
    datas=[
        (os.path.join(ROOT, "templates"), "templates"),
        (os.path.join(ROOT, "static", "style.css"), "static"),
        (os.path.join(ROOT, "static", "dashboard.css"), "static"),
        (os.path.join(ROOT, "static", "dashboard.js"), "static"),
        (os.path.join(ROOT, "LICENSES"), "LICENSES"),
    ],
    hiddenimports=["webview.platforms.edgechromium", "reportlab.graphics.barcode.common"],
    excludes=["tkinter", "pytest", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="NetGuard",
    icon=os.path.join(SPECPATH, "netguard.ico"),
    version=os.path.join(SPECPATH, "version_info.txt"),
    console=False,          # no black console window
    upx=False,              # UPX-packed exes trigger antivirus false positives
)
coll = COLLECT(exe, a.binaries, a.datas, name="NetGuard", upx=False)
