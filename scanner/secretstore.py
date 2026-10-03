"""Encrypt secrets (SMTP password, Telegram token) at rest.

Windows: DPAPI (CryptProtectData), tied to the signed-in Windows user, so a copied database
is useless on another account or PC. Elsewhere the value is only obfuscated (base64) and
marked as such.
"""
import base64
import ctypes
import sys

_IS_WINDOWS = sys.platform.startswith("win")

if _IS_WINDOWS:
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _UI_FORBIDDEN = 0x1

    def _call(func, data):
        buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _BLOB()
        if not func(ctypes.byref(blob_in), None, None, None, None, _UI_FORBIDDEN, ctypes.byref(blob_out)):
            raise OSError("DPAPI call failed")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(blob_out.pbData)


def protect(text):
    if not text:
        return ""
    raw = text.encode("utf-8")
    if _IS_WINDOWS:
        return "dpapi:" + base64.b64encode(_call(_crypt32.CryptProtectData, raw)).decode()
    return "plain:" + base64.b64encode(raw).decode()


def unprotect(value):
    if not value:
        return ""
    kind, _, data = value.partition(":")
    try:
        raw = base64.b64decode(data)
        if kind == "dpapi" and _IS_WINDOWS:
            return _call(_crypt32.CryptUnprotectData, raw).decode("utf-8")
        if kind == "plain":
            return raw.decode("utf-8")
    except (OSError, ValueError):
        pass
    return ""  # unreadable (e.g. database copied from another Windows account)
