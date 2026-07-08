"""Tests for the hardening controls added in the security review."""

import pytest

from backend.app.security import (
    ValidationError,
    is_disallowed_target_host,
    resolve_within,
    sanitize_filename,
    validate_git_ref,
    validate_git_url,
)


class TestGitValidation:
    def test_accepts_https_url(self):
        assert validate_git_url("https://github.com/org/repo.git")

    @pytest.mark.parametrize(
        "bad",
        [
            "https://x.com/r; rm -rf /",          # command separator
            "--upload-pack=/bin/sh",              # option injection
            "file:///etc/passwd",                 # disallowed scheme
            "https://x.com/r\nrm -rf /",          # newline injection
            "",                                    # empty
        ],
    )
    def test_rejects_malicious_urls(self, bad):
        with pytest.raises(ValidationError):
            validate_git_url(bad)

    def test_accepts_simple_branch(self):
        assert validate_git_ref("main") == "main"
        assert validate_git_ref("feature/x-1") == "feature/x-1"

    @pytest.mark.parametrize(
        "bad",
        ["../../etc", "-x", "a b", "a;b", "a$(id)", "a..b"],
    )
    def test_rejects_bad_branches(self, bad):
        with pytest.raises(ValidationError):
            validate_git_ref(bad)


class TestFilenameAndPaths:
    def test_sanitize_strips_traversal(self):
        assert sanitize_filename("../../evil.zip") == "evil.zip"
        assert sanitize_filename("/etc/passwd") == "passwd"

    @pytest.mark.parametrize("bad", ["", "..", "."])
    def test_sanitize_rejects_invalid(self, bad):
        with pytest.raises(ValidationError):
            sanitize_filename(bad)

    def test_resolve_within_allows_child(self, tmp_path):
        (tmp_path / "sub").mkdir()
        resolved = resolve_within(str(tmp_path), str(tmp_path / "sub" / "f.txt"))
        assert str(resolved).startswith(str(tmp_path))

    def test_resolve_within_blocks_escape(self, tmp_path):
        with pytest.raises(ValidationError):
            resolve_within(str(tmp_path / "base"), str(tmp_path / "outside.txt"))


class TestSSRFGuard:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "169.254.169.254"])
    def test_blocks_loopback_and_metadata(self, host):
        assert is_disallowed_target_host(host, block_private=False) is True

    def test_allows_public_host(self):
        # A routable public IP should be permitted when private ranges allowed.
        assert is_disallowed_target_host("8.8.8.8", block_private=False) is False


class TestSafeZipMembers:
    def test_rejects_zip_slip(self, tmp_path):
        import zipfile

        from backend.app.security import safe_zip_members

        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../escape.txt", "x")

        with zipfile.ZipFile(archive) as zf:
            with pytest.raises(ValidationError):
                safe_zip_members(zf, str(tmp_path / "extract"), 10_000)

    def test_rejects_zip_bomb(self, tmp_path):
        import zipfile

        from backend.app.security import safe_zip_members

        archive = tmp_path / "big.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("a.txt", "A" * 5000)

        with zipfile.ZipFile(archive) as zf:
            with pytest.raises(ValidationError):
                safe_zip_members(zf, str(tmp_path / "extract"), 100)


@pytest.mark.asyncio
async def test_registration_ignores_client_role(client):
    """A self-registering user must never receive the ADMIN role by asking."""
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "attacker",
            "email": "attacker@example.com",
            "password": "correct horse battery",
            "role": "admin",  # attacker tries to escalate
        },
    )
    assert resp.status_code == 200, resp.text
    # First user bootstraps admin; but the SECOND user must not be admin even
    # though they asked for it.
    resp2 = await client.post(
        "/api/auth/register",
        json={
            "username": "attacker2",
            "email": "attacker2@example.com",
            "password": "correct horse battery",
            "role": "admin",
        },
    )
    assert resp2.status_code == 200, resp2.text
    assert resp2.json()["role"] != "admin"


@pytest.mark.asyncio
async def test_metrics_ingestion_requires_agent_auth(client, sample_metric_data):
    """Posting metrics without agent credentials must be rejected."""
    resp = await client.post("/api/metrics/batch", json={"metrics": [sample_metric_data]})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_password_minimum_length_enforced(client):
    resp = await client.post(
        "/api/auth/register",
        json={"username": "shorty", "email": "s@example.com", "password": "short"},
    )
    assert resp.status_code == 422
