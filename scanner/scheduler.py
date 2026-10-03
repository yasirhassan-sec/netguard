"""Pro: scheduled automatic scans.

Slots are fixed wall-clock times (daily at 03:00, weekly on Sunday at 03:00, or every N hours
from midnight). A background thread checks every 30 s and runs a slot that has passed since
the last scheduled run, so a scan missed while the PC was off runs once when NetGuard starts.
"""
import logging
import threading
import time
from datetime import datetime, timedelta

log = logging.getLogger("netguard.scheduler")
HOUR_CHOICES = (1, 2, 3, 4, 6, 8, 12, 24)


def _hhmm(text):
    try:
        h, m = (int(x) for x in str(text).split(":", 1))
        if 0 <= h < 24 and 0 <= m < 60:
            return h, m
    except ValueError:
        pass
    return 3, 0


def previous_slot(s, now):
    """The most recent scheduled time at or before now (None when scheduling is off)."""
    if not s["schedule_enabled"]:
        return None
    freq = s["schedule_frequency"]
    if freq == "hourly":
        n = s["schedule_hours"] if s["schedule_hours"] in HOUR_CHOICES else 6
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        steps = int((now - midnight).total_seconds() // (n * 3600))
        return midnight + timedelta(hours=steps * n)
    h, m = _hhmm(s["schedule_time"])
    slot = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if freq == "weekly":
        slot -= timedelta(days=(slot.weekday() - int(s["schedule_weekday"])) % 7)
        if slot > now:
            slot -= timedelta(days=7)
        return slot
    return slot if slot <= now else slot - timedelta(days=1)  # daily


def next_slot(s, now):
    prev = previous_slot(s, now)
    if prev is None:
        return None
    if s["schedule_frequency"] == "hourly":
        n = s["schedule_hours"] if s["schedule_hours"] in HOUR_CHOICES else 6
        return prev + timedelta(hours=n)
    return prev + timedelta(days=7 if s["schedule_frequency"] == "weekly" else 1)


def is_due(s, now):
    prev = previous_slot(s, now)
    if prev is None:
        return False
    last = s.get("last_scheduled_run")
    return not last or datetime.fromisoformat(last) < prev


class Scheduler:
    def __init__(self, get_settings, save_state, is_pro, run_scans, interval=30):
        self.get_settings, self.save_state = get_settings, save_state
        self.is_pro, self.run_scans, self.interval = is_pro, run_scans, interval
        self._started = False

    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="scheduler").start()

    def tick(self, now=None):
        now = now or datetime.now()
        s = self.get_settings()
        if not (s["schedule_enabled"] and self.is_pro(s) and is_due(s, now)):
            return False
        self.save_state(now.isoformat(timespec="seconds"))  # mark first: never double-run a slot
        log.info("Scheduled scan due (slot %s)", previous_slot(s, now))
        self.run_scans(s["schedule_mode"])
        return True

    def _loop(self):
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("Scheduled scan failed")
            time.sleep(self.interval)
