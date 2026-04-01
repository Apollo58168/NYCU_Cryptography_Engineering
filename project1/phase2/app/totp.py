"""
Manual TOTP implementation following RFC 6238 (TOTP) and RFC 4226 (HOTP).

Algorithm:
  1. T = floor(UnixTimestamp / 30)          — current time step
  2. HOTP(K, T):
     a. msg  = T as 8-byte big-endian integer
     b. HS   = HMAC-SHA1(K, msg)            — 20-byte digest
     c. offset = HS[19] & 0x0F
     d. P    = HS[offset : offset+4] interpreted as big-endian uint32
     e. code = (P & 0x7FFFFFFF) mod 10^6   — 6-digit OTP
"""

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote


# ---------------------------------------------------------------------------
# Secret generation
# ---------------------------------------------------------------------------

def generate_secret() -> str:
    """Return a fresh 20-byte TOTP secret encoded as Base32 (uppercase)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


# ---------------------------------------------------------------------------
# Core HOTP / TOTP
# ---------------------------------------------------------------------------

def _hotp(key: bytes, counter: int) -> str:
    """Compute a 6-digit HOTP value for *key* and *counter* (RFC 4226)."""
    msg = struct.pack(">Q", counter)                  # 8-byte big-endian
    digest = hmac.new(key, msg, hashlib.sha1).digest()  # 20-byte HMAC-SHA1

    # Dynamic truncation
    offset = digest[-1] & 0x0F
    p = struct.unpack(">I", digest[offset : offset + 4])[0]
    code = (p & 0x7FFFFFFF) % 1_000_000

    return str(code).zfill(6)


def get_totp_token(secret: str, time_step: int | None = None) -> str:
    """
    Return the 6-digit TOTP code for *secret* at the given *time_step*.

    If *time_step* is None, use the current Unix time divided by 30.
    """
    if time_step is None:
        time_step = int(time.time()) // 30
    key = base64.b32decode(secret.upper().strip())
    return _hotp(key, time_step)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify *code* against the TOTP secret.

    Accepts codes from (current_step - window) to (current_step + window),
    which gives a ±30-second grace period when window=1.
    """
    current_step = int(time.time()) // 30
    for delta in range(-window, window + 1):
        if get_totp_token(secret, current_step + delta) == code.strip():
            return True
    return False


# ---------------------------------------------------------------------------
# Helpers for QR code / provisioning URI
# ---------------------------------------------------------------------------

def generate_otpauth_uri(secret: str, username: str,
                          issuer: str = "CryptoEng2FA") -> str:
    """Build an otpauth:// URI understood by Google Authenticator.

    Key URI Format (https://github.com/google/google-authenticator/wiki/Key-Uri-Format):
      otpauth://totp/<issuer>:<account>?secret=<secret>&issuer=<issuer>

    Rules:
    - The colon separating issuer and account in the label MUST be a
      literal colon (not %3A).
    - Only include the two mandatory parameters (secret + issuer).
      Adding algorithm/digits/period causes parse failures in some GA
      versions and makes the QR code unnecessarily dense.
    """
    label = f"{quote(issuer, safe='')}:{quote(username, safe='')}"
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
    )


def generate_qr_code_b64(data: str) -> str:
    """
    Return a base64-encoded PNG of the QR code for *data*.
    Returns an empty string if the qrcode / Pillow library is unavailable.
    """
    try:
        import qrcode  # type: ignore
        import qrcode.constants  # type: ignore

        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,  # good balance: ~15% recovery
            box_size=10,   # pixels per "box" – gives a large, easy-to-scan image
            border=4,      # quiet zone (minimum 4 per spec)
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("utf-8")
    except Exception:
        return ""
