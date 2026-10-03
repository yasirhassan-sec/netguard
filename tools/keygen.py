"""NetGuard licence key generator - FOR THE SELLER ONLY. Never ship this or the private key.

  python tools/keygen.py init
      Creates your signing key pair (once). The private key is stored OUTSIDE the project in
      %USERPROFILE%\\.netguard-signing\\ . Back it up somewhere safe: if you lose it you cannot
      issue keys that existing app versions accept; if it leaks, anyone can make keys.

  python tools/keygen.py issue --name "Jane Doe" --email jane@example.com [--days 365] [--seats 1]
      Prints a licence key to send to a customer. Without --days the licence never expires.
"""
import argparse
import base64
import os
import sys
import uuid
from datetime import date, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import licensing  # noqa: E402

KEY_DIR = os.path.join(os.path.expanduser("~"), ".netguard-signing")
KEY_FILE = os.path.join(KEY_DIR, "netguard_signing_key.pem")


def init():
    if os.path.exists(KEY_FILE):
        sys.exit(f"A signing key already exists at {KEY_FILE}. Refusing to overwrite it.")
    os.makedirs(KEY_DIR, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with open(KEY_FILE, "wb") as f:
        f.write(pem)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"Private key saved to: {KEY_FILE}  (BACK IT UP, NEVER SHARE OR COMMIT IT)")
    print("Put this public key in scanner/licensing.py as PUBLIC_KEY_B64:")
    print(base64.b64encode(public).decode())


def load_private():
    if not os.path.exists(KEY_FILE):
        sys.exit("No signing key yet. Run: python tools/keygen.py init")
    with open(KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def issue(args):
    payload = {
        "lic": uuid.uuid4().hex[:12].upper(),
        "name": args.name,
        "email": args.email,
        "edition": "pro",
        "seats": args.seats,
        "issued": date.today().isoformat(),
        "exp": (date.today() + timedelta(days=args.days)).isoformat() if args.days else None,
    }
    key = licensing.make_key(payload, load_private())
    public = load_private().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    licensing.parse_key(key, base64.b64encode(public).decode())  # self-check
    print(f"Licence {payload['lic']} for {args.name} <{args.email}>, expires: {payload['exp'] or 'never'}")
    print(key)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p = sub.add_parser("issue")
    p.add_argument("--name", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--days", type=int, default=0)
    p.add_argument("--seats", type=int, default=1)
    a = ap.parse_args()
    init() if a.cmd == "init" else issue(a)
