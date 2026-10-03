"""Editions and licence keys.

A licence key is  NG1-<payload>.<signature>  (both base64url). The payload is JSON:
{"lic": id, "name": customer, "email": ..., "edition": "pro", "seats": n, "issued": date, "exp": date|null}
signed with the seller's Ed25519 private key (tools/keygen.py). The app only holds the public
key below, so it can verify keys offline but cannot create them.
"""
import base64
import json
from datetime import date, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Seller's public key (raw 32 bytes, base64), made with: python tools/keygen.py init
# Safe to publish. The matching private key must never be in this repository.
PUBLIC_KEY_B64 = "aNUtCOlJ6NeWFk9kZYsGqk3O1WAWeaXAg5isqsLB7q4="

KEY_PREFIX = "NG1-"
SIGNING_CONTEXT = b"NetGuard licence v1\n"  # domain separation for signatures
TRIAL_DAYS = 14

PRO_FEATURES = {
    "scheduler": "Scheduled automatic scans",
    "sites": "Multiple sites and networks",
    "branding": "Branded reports",
    "notifications": "Email and Telegram alerts",
}
FREE_SITE_LIMIT = 1


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_key(key, public_key_b64=None):
    """Verify a key and return its payload. Raises ValueError with a user-facing reason."""
    key = (key or "").strip().replace("\n", "").replace(" ", "")
    if not key.startswith(KEY_PREFIX) or "." not in key:
        raise ValueError("This doesn't look like a NetGuard licence key.")
    payload_b64, _, sig_b64 = key[len(KEY_PREFIX):].partition(".")
    try:
        payload_raw, signature = _b64d(payload_b64), _b64d(sig_b64)
        public = Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64 or PUBLIC_KEY_B64))
    except ValueError:
        raise ValueError("The licence key is damaged or incomplete.")
    try:
        public.verify(signature, SIGNING_CONTEXT + payload_raw)
    except InvalidSignature:
        raise ValueError("The licence key is not valid.")
    payload = json.loads(payload_raw)
    if payload.get("edition") != "pro":
        raise ValueError("Unknown licence edition.")
    return payload


def make_key(payload, private_key):
    """Used by tools/keygen.py only."""
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return KEY_PREFIX + _b64e(raw) + "." + _b64e(private_key.sign(SIGNING_CONTEXT + raw))


def status(settings, today=None):
    """Current edition: Pro via licence or trial, else Free."""
    today = today or date.today()
    info = {"edition": "free", "source": "free", "trial_days": TRIAL_DAYS, "features": PRO_FEATURES,
            "trial_available": not settings.get("trial_started"), "error": None}

    key = settings.get("license_key")
    if key:
        try:
            p = parse_key(key)
        except ValueError as exc:
            info["error"] = str(exc)
        else:
            exp = p.get("exp")
            days_left = (date.fromisoformat(exp) - today).days if exp else None
            lic = {"name": p.get("name", ""), "email": p.get("email", ""), "seats": p.get("seats", 1),
                   "exp": exp, "id": p.get("lic", ""), "days_left": days_left}
            if days_left is None or days_left >= 0:
                return {**info, "edition": "pro", "source": "license", "license": lic}
            info.update(source="expired", license=lic, error=f"Your licence expired on {exp}.")

    started = settings.get("trial_started")
    if started:
        used = (today - datetime.fromisoformat(started).date()).days
        left = TRIAL_DAYS - used
        if left > 0:
            return {**info, "edition": "pro", "source": "trial", "days_left": left}
        if info["source"] == "free":
            info["source"] = "trial_ended"
    return info


def is_pro(settings):
    return status(settings)["edition"] == "pro"
