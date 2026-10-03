import subprocess
import sys

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# Keep console windows from flashing up when the dashboard shells out on Windows.
_FLAGS = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0


def run_cmd(args, timeout=15):
    """Run a command and return (stdout_text, returncode). Never raises."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=_FLAGS)
    except (OSError, subprocess.TimeoutExpired):
        return "", -1
    # Windows console tools (netsh, arp, route) print in the OEM code page.
    encoding = "oem" if IS_WINDOWS else "utf-8"
    return proc.stdout.decode(encoding, errors="replace"), proc.returncode


def normalize_mac(mac):
    if not mac:
        return None
    return mac.replace("-", ":").lower()
