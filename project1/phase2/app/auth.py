"""
Password hashing utilities using PBKDF2-HMAC-SHA256 with a random salt.
No third-party libraries required — only the Python standard library.
"""

import hashlib
import hmac
import secrets


_ITERATIONS = 260_000   # OWASP 2023 recommendation for PBKDF2-SHA256
_HASH_NAME   = "sha256"


def hash_password(password: str) -> str:
    """Return a salted PBKDF2 hash of *password*, stored as 'salt_hex:dk_hex'."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(_HASH_NAME, password.encode(), salt, _ITERATIONS)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if *password* matches *stored_hash*."""
    try:
        salt_hex, dk_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(_HASH_NAME, password.encode(), salt, _ITERATIONS)
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False
