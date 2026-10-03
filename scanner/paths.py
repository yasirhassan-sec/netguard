"""Where NetGuard keeps its data, logs and reports.

Development: ./data inside the project.  Installed (frozen) build: %LOCALAPPDATA%\\NetGuard
(~/.local/share/netguard on Linux). Override with the NETGUARD_HOME environment variable.
"""
import logging
import logging.handlers
import os
import sys

APP_NAME = "NetGuard"
FROZEN = getattr(sys, "frozen", False)

# Read-only resources (templates/static) live next to the code, or in the PyInstaller bundle.
RESOURCE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _default_home():
    if not FROZEN:
        return os.path.join(RESOURCE_DIR, "data")
    if sys.platform.startswith("win"):
        return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_NAME)
    return os.path.join(os.path.expanduser("~"), ".local", "share", "netguard")


DATA_DIR = os.environ.get("NETGUARD_HOME") or _default_home()
LOG_DIR = os.path.join(DATA_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def setup_logging(level=logging.INFO):
    """Rotating log file (5 x 1 MB) plus console output."""
    root = logging.getLogger()
    if any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(os.path.join(LOG_DIR, "netguard.log"),
                                              maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.setLevel(level)
    root.addHandler(fh)
    root.addHandler(ch)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
