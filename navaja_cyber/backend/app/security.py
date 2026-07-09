"""Shared security primitives: input validation and safe-path helpers.

Centralises the checks used across routers so hardening rules live in one place
and are covered by a single set of tests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from pathlib import Path

# Git URLs we are willing to clone. Anything else is rejected before it can
# reach a subprocess argument list.
_GIT_URL_RE = re.compile(r"^(https|git|ssh)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
# Conservative branch/ref grammar (no shell metacharacters, no leading dash,
# no ".." path traversal, matching git's own ref rules closely enough).
_GIT_REF_RE = re.compile(r"^(?!-)[A-Za-z0-9._/-]{1,255}$")


class ValidationError(ValueError):
    """Raised when untrusted input fails a security check."""


def validate_git_url(url: str) -> str:
    """Validate a git clone URL, rejecting shell/option injection vectors.

    Returns the URL unchanged when valid, otherwise raises ``ValidationError``.
    """
    if not url or len(url) > 2048:
        raise ValidationError("git_url is empty or too long")
    if url.startswith("-"):
        raise ValidationError("git_url may not start with '-'")
    if any(c in url for c in ("\x00", "\n", "\r", " ", "\t")):
        raise ValidationError("git_url contains illegal whitespace/control characters")
    if not _GIT_URL_RE.match(url):
        raise ValidationError("git_url scheme not allowed (use https/git/ssh)")
    return url


def validate_git_ref(ref: str) -> str:
    """Validate a branch/tag name used as a git argument."""
    if not _GIT_REF_RE.match(ref or ""):
        raise ValidationError("invalid branch/ref name")
    if ".." in ref:
        raise ValidationError("branch/ref may not contain '..'")
    return ref


def sanitize_filename(name: str) -> str:
    """Reduce an uploaded filename to a safe basename with no traversal."""
    if not name:
        raise ValidationError("empty filename")
    base = Path(name).name  # strips any directory components / traversal
    base = base.replace("\x00", "")
    if not base or base in (".", ".."):
        raise ValidationError("invalid filename")
    return base


def resolve_within(base_dir: str, candidate: str) -> Path:
    """Resolve ``candidate`` and ensure it stays inside ``base_dir``.

    Guards against path traversal (``..``) and symlink escapes. Raises
    ``ValidationError`` if the resolved path escapes the base directory.
    """
    base = Path(base_dir).resolve(strict=False)
    target = Path(candidate).resolve(strict=False)
    if base == target:
        return target
    if base not in target.parents:
        raise ValidationError("path escapes the permitted base directory")
    return target


def safe_zip_members(zip_ref, extract_dir: str, max_total_bytes: int) -> list[str]:
    """Return archive member names that are safe to extract.

    Rejects absolute paths, traversal, and archives whose uncompressed size
    exceeds ``max_total_bytes`` (zip-bomb protection). Raises on violation.
    """
    base = Path(extract_dir).resolve()
    total = 0
    names: list[str] = []
    for info in zip_ref.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        dest = (base / name).resolve()
        if base != dest and base not in dest.parents:
            raise ValidationError(f"unsafe path in archive: {name}")
        total += info.file_size
        if total > max_total_bytes:
            raise ValidationError("archive exceeds maximum uncompressed size")
        names.append(name)
    return names


# Networks that internal services / SSRF payloads typically target. Used to
# warn/block when a user asks the platform to connect outbound to a host.
def is_disallowed_target_host(host: str, *, block_private: bool = True) -> bool:
    """Return True if ``host`` resolves to a loopback/link-local/metadata range.

    Helps mitigate SSRF where a user supplies a host the server will connect to
    (e.g. database analysis). When ``block_private`` is False only loopback and
    the cloud metadata address are rejected.
    """
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable: let the caller's connection attempt fail normally.
        return False
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return True
        # Cloud metadata endpoint.
        if ip_str == "169.254.169.254":
            return True
        if block_private and ip.is_private:
            return True
    return False


class UploadTooLarge(ValidationError):
    """Raised when a streamed upload exceeds the configured maximum size."""


async def stream_upload_to_path(
    upload, dest_path: str, max_bytes: int, chunk_size: int = 1024 * 1024
) -> dict:
    """Stream a Starlette/FastAPI UploadFile to disk without buffering it all.

    Reads in ``chunk_size`` blocks, aborting (and removing the partial file) as
    soon as the total exceeds ``max_bytes``. Computes SHA-256/MD5 incrementally
    and captures the first bytes for MIME sniffing. Returns a dict with
    ``size``, ``sha256``, ``md5`` and ``head`` (first up to 2048 bytes).
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total = 0
    head = b""
    dest = Path(dest_path)
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = await upload.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLarge(
                        f"upload exceeds maximum size of {max_bytes} bytes"
                    )
                if len(head) < 2048:
                    head += chunk[: 2048 - len(head)]
                sha256.update(chunk)
                md5.update(chunk)
                out.write(chunk)
    except UploadTooLarge:
        dest.unlink(missing_ok=True)
        raise
    return {
        "size": total,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "head": head,
    }
