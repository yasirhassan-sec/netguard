"""NetGuard desktop app: runs the local server and shows the dashboard in a native window.

Run:  python desktop.py      (packaged build: NetGuard.exe)
Falls back to the default browser if no WebView engine is available.
"""
import logging
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

import app as netguard
from scanner import __version__

log = logging.getLogger("netguard.desktop")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_up(url, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url + "api/settings", timeout=1)
            return True
        except OSError:
            time.sleep(0.15)
    return False


def _single_instance():
    """Return a socket that holds a fixed port as an 'already running' lock, or None."""
    lock = socket.socket()
    try:
        lock.bind(("127.0.0.1", 47613))
        return lock
    except OSError:
        return None


def main():
    lock = _single_instance()
    if lock is None:
        # Another NetGuard window is already open; avoid two scanners fighting over the same DB.
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, "NetGuard is already running.", "NetGuard", 0x40)
        except Exception:
            print("NetGuard is already running.")
        return

    netguard.start_background()
    port = _free_port()
    url = f"http://127.0.0.1:{port}/"
    threading.Thread(target=netguard.serve, args=(port,), daemon=True, name="server").start()
    if not _wait_until_up(url):
        log.error("Server did not start on %s", url)
        sys.exit(1)

    try:
        import webview
    except ImportError:
        webview = None

    if webview is None:
        log.warning("pywebview not installed; opening the default browser")
        webbrowser.open(url)
        threading.Event().wait()  # keep the server alive until the process is killed
        return

    webview.create_window(f"NetGuard {__version__}", url, width=1440, height=920, min_size=(980, 640),
                          background_color="#060f22", text_select=True)
    # private_mode keeps no cookies/cache between runs; the page holds no secrets worth persisting.
    webview.start(private_mode=True)
    log.info("Window closed, exiting")


if __name__ == "__main__":
    main()
