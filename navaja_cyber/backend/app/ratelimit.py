"""Application-wide rate limiting.

Wraps ``slowapi`` so the ``RATE_LIMIT_*`` settings are actually enforced. Limits
are expressed as callables that read settings at request time, so operators can
tune them via environment variables without code changes.

Sensitive endpoints (login, registration, flag submission) get strict per-client
limits to slow credential stuffing / brute-force and flag guessing.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from backend.app.config import settings


def _client_key(request: Request) -> str:
    """Derive the rate-limit bucket key for a request.

    Defaults to the peer address. When ``rate_limit_trust_forwarded`` is enabled
    (only safe behind a trusted reverse proxy) the left-most X-Forwarded-For
    entry is used so limits track the real client rather than the proxy.
    """
    if settings.rate_limit_trust_forwarded:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return get_remote_address(request)


# Empty storage_uri => in-memory (single worker). Provide a redis:// URI in
# production multi-worker deployments for globally-consistent limits.
# NOTE: headers_enabled is intentionally False. When True, slowapi injects
# X-RateLimit-* headers by requiring every decorated endpoint to accept a
# `response: Response` parameter; endpoints returning Pydantic models (most of
# ours) would raise at runtime once the limiter is enabled. Enforcement (429)
# works regardless of this flag.
limiter = Limiter(
    key_func=_client_key,
    enabled=settings.rate_limit_enabled,
    storage_uri=settings.rate_limit_storage_uri or "memory://",
    default_limits=[lambda: f"{settings.rate_limit_default}/minute"],
    headers_enabled=False,
)


# Named limits used as decorators (callables so config changes take effect).
def auth_limit() -> str:
    return f"{settings.rate_limit_auth}/minute"


def register_limit() -> str:
    return f"{settings.rate_limit_register}/minute"


def submit_limit() -> str:
    return f"{settings.rate_limit_submit}/minute"


def scan_limit() -> str:
    return f"{settings.rate_limit_scan}/minute"
