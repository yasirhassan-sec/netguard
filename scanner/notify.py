"""Pro: email (SMTP) and Telegram alerts. One message per scan, listing its new alerts."""
import json
import logging
import re
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("netguard.notify")
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$")


def _one_line(text, limit=200):
    """Strip control characters (prevents header injection) and shorten."""
    return re.sub(r"[\r\n\t\x00-\x1f]+", " ", str(text)).strip()[:limit]


def compose(alerts, site=None):
    title = f"NetGuard: {len(alerts)} new alert{'s' if len(alerts) != 1 else ''}"
    if site:
        title += f" on {site}"
    lines = [f"[{a['severity'].upper()}] {_one_line(a['title'])}" + (f" - {_one_line(a['detail'])}" if a["detail"] else "")
             for a in sorted(alerts, key=lambda a: SEV_RANK.get(a["severity"], 9))]
    return title, "\n".join(lines) + "\n\nOpen NetGuard for details and recommended fixes."


def select(alerts, min_severity):
    limit = SEV_RANK.get(min_severity, 1)
    return [a for a in alerts if SEV_RANK.get(a["severity"], 9) <= limit and a["kind"] != "scan_completed"]


def send_email(s, subject, body):
    host, to, sender = s["smtp_host"].strip(), s["email_to"].strip(), (s["email_from"] or s["smtp_user"]).strip()
    if not (host and to and sender):
        raise ValueError("Fill in SMTP server, sender and recipient.")
    msg = EmailMessage()
    msg["Subject"], msg["From"] = _one_line(subject), _one_line(sender)
    msg["To"] = ", ".join(_one_line(a) for a in to.split(",") if a.strip())
    msg.set_content(body)
    ctx = ssl.create_default_context()
    port = int(s["smtp_port"])
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
    else:
        server = smtplib.SMTP(host, port, timeout=20)
        server.starttls(context=ctx)  # never send credentials unencrypted
    with server:
        if s["smtp_user"]:
            server.login(s["smtp_user"], s["smtp_password"])
        server.send_message(msg)


def send_telegram(s, text):
    token, chat = s["telegram_token"].strip(), s["telegram_chat_id"].strip()
    if not TOKEN_RE.match(token):
        raise ValueError("The Telegram bot token doesn't look right (it comes from @BotFather).")
    if not CHAT_RE.match(chat):
        raise ValueError("The Telegram chat ID should be a number (or @channelname).")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps({"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        if not json.load(resp).get("ok"):
            raise RuntimeError("Telegram rejected the message.")


def dispatch(alerts, s, site=None):
    """Send the alerts through every enabled channel. Returns {channel: 'sent' | error}."""
    chosen = select(alerts, s["notify_min_severity"])
    if not chosen:
        return {}
    subject, body = compose(chosen, site)
    results = {}
    for channel, enabled, send in (("email", s["email_enabled"], lambda: send_email(s, subject, body)),
                                   ("telegram", s["telegram_enabled"], lambda: send_telegram(s, f"{subject}\n\n{body}"))):
        if not enabled:
            continue
        try:
            send()
            results[channel] = "sent"
        except Exception as exc:  # a broken channel must never break a scan
            log.warning("%s notification failed: %s", channel, exc)
            results[channel] = f"failed: {exc}"
    return results
