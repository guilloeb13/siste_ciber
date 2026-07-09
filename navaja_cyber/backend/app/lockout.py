"""Account lockout after repeated failed logins.

Backed by Redis so the counter is shared across workers. When Redis is not
available (e.g. unit tests, or the cache is down) every function degrades to a
no-op: rate limiting still provides brute-force protection, but login never
breaks because of a missing cache.
"""

from __future__ import annotations

import hashlib
from typing import Any

from backend.app.config import settings

_PREFIX = "lockout:login:"


def _key(username: str) -> str:
    # Hash the username so we never store raw identifiers as cache keys.
    digest = hashlib.sha256(username.strip().lower().encode()).hexdigest()
    return f"{_PREFIX}{digest}"


async def is_locked_out(redis: Any, username: str) -> bool:
    """Return True if the account currently exceeds the failure threshold."""
    if redis is None or not settings.lockout_enabled or not username:
        return False
    try:
        raw = await redis.get(_key(username))
    except Exception:
        return False
    try:
        return raw is not None and int(raw) >= settings.lockout_max_attempts
    except (TypeError, ValueError):
        return False


async def record_failure(redis: Any, username: str) -> None:
    """Increment the failure counter and (re)set its expiry window."""
    if redis is None or not settings.lockout_enabled or not username:
        return
    key = _key(username)
    try:
        # RedisService wraps a redis.asyncio client; use it directly.
        client = getattr(redis, "client", None)
        if client is None:
            return
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, settings.lockout_window_seconds)
    except Exception:
        # Never let cache issues block the auth path.
        return


async def clear_failures(redis: Any, username: str) -> None:
    """Reset the failure counter after a successful login."""
    if redis is None or not username:
        return
    try:
        await redis.delete(_key(username))
    except Exception:
        return
