"""Centralised password/token hashing using Argon2id.

Replaces the unmaintained ``passlib`` + ``bcrypt`` stack (which is incompatible
with bcrypt >= 4.1 and imposes a 72-byte input limit). Argon2id is the current
OWASP-recommended password hashing algorithm and has no length cap.

All hashing goes through this module so parameters can be tuned in one place.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Argon2id with library defaults (sensible, OWASP-aligned). Tune here if the
# deployment's threat model / hardware calls for stronger parameters.
_hasher = PasswordHasher()

# A fixed dummy hash used to keep verification timing roughly constant when the
# target user/agent does not exist (mitigates account enumeration by timing).
_DUMMY_HASH = _hasher.hash("navaja-dummy-value-for-constant-time-verify")


def hash_secret(secret: str) -> str:
    """Hash a password or token for storage."""
    return _hasher.hash(secret)


def verify_secret(hashed: str, secret: str) -> bool:
    """Verify ``secret`` against a stored hash. Returns bool, never raises."""
    try:
        return _hasher.verify(hashed, secret)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(hashed: str) -> bool:
    """True if the stored hash used weaker parameters and should be upgraded."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except Exception:
        return False


def dummy_verify() -> None:
    """Perform a throwaway verification to equalise timing on the failure path."""
    try:
        _hasher.verify(_DUMMY_HASH, "wrong")
    except Exception:
        pass
