"""Copy the licence files of every bundled third-party package into LICENSES/.

Shipping these notices is required by the BSD/MIT-style licences of NetGuard's dependencies.
Run before each release:  python packaging/collect_licenses.py
"""
import os
from importlib import metadata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "LICENSES")

# Runtime dependencies that end up inside NetGuard.exe (plus their own dependencies).
PACKAGES = ["flask", "werkzeug", "jinja2", "markupsafe", "itsdangerous", "click", "blinker",
            "psutil", "reportlab", "pywebview", "proxy_tools", "bottle", "pythonnet", "clr_loader",
            "cffi", "pycparser", "typing_extensions", "cryptography"]

DATA_NOTICES = """\
Data sources
============
* IEEE OUI registry (MAC address -> manufacturer), downloaded by the user at runtime from
  https://standards-oui.ieee.org/ . IEEE Registration Authority data.
* NIST National Vulnerability Database (optional online CVE lookup).
  This product uses the NVD API but is not endorsed or certified by the NVD.
"""


def main():
    os.makedirs(OUT, exist_ok=True)
    summary = ["NetGuard third-party notices", "=" * 28, ""]
    for name in PACKAGES:
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        lic = dist.metadata.get("License-Expression") or dist.metadata.get("License") or ""
        lic = lic.splitlines()[0][:60] if lic else "see file"
        summary.append(f"{dist.metadata['Name']} {dist.version} - {lic}")
        texts = [f for f in (dist.files or []) if ("licen" in f.name.lower() or "copying" in f.name.lower()
                 or "notice" in f.name.lower()) and "darkgarden" not in str(f).lower()]  # GPL font is not shipped
        for f in texts:
            src = dist.locate_file(f)
            if os.path.isfile(src):
                with open(src, encoding="utf-8", errors="replace") as fh:
                    body = fh.read()
                with open(os.path.join(OUT, f"{dist.metadata['Name']}-{f.name}.txt"), "w", encoding="utf-8") as fh:
                    fh.write(body)
    summary += ["", "Python itself: Python Software Foundation License.", "", DATA_NOTICES]
    with open(os.path.join(OUT, "THIRD_PARTY_NOTICES.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(summary))
    print("\n".join(summary))


if __name__ == "__main__":
    main()
