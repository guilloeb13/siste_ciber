"""Test static analysis module."""

import pytest
from uuid import uuid4

from analysis.static_analysis import normalize_findings, detect_secrets


def test_normalize_bandit_findings():
    """Test normalization of Bandit findings."""
    scan_id = uuid4()

    raw_results = [
        {
            "test_id": "B101",
            "test_name": "assert_used",
            "issue_text": "Use of assert detected",
            "issue_severity": "LOW",
            "filename": "/app/test.py",
            "line_number": 10,
            "code": "assert x > 0",
        }
    ]

    findings = normalize_findings(raw_results, "bandit", scan_id)

    assert len(findings) == 1
    assert findings[0]["source"] == "bandit"
    assert findings[0]["rule_id"] == "B101"
    assert findings[0]["severity"] == "low"
    assert findings[0]["file_path"] == "/app/test.py"


def test_normalize_pip_audit_findings():
    """Test normalization of pip-audit findings."""
    scan_id = uuid4()

    raw_results = [
        {
            "package": "requests",
            "version": "2.25.0",
            "vuln_id": "CVE-2023-12345",
            "fix_versions": ["2.28.0", "2.29.0"],
            "description": "Security vulnerability in requests",
        }
    ]

    findings = normalize_findings(raw_results, "pip-audit", scan_id)

    assert len(findings) == 1
    assert findings[0]["source"] == "pip-audit"
    assert "requests" in findings[0]["title"]
    assert findings[0]["severity"] == "high"
    assert "2.28.0" in findings[0]["recommendation"]


def test_normalize_secrets_findings():
    """Test normalization of secret detection findings."""
    scan_id = uuid4()

    raw_results = [
        {
            "file": "config.py",
            "line": 5,
            "type": "api_key",
            "pattern": "api_key pattern",
            "snippet": "API_KEY = 'secret123...'",
        }
    ]

    findings = normalize_findings(raw_results, "secrets", scan_id)

    assert len(findings) == 1
    assert findings[0]["source"] == "secrets"
    assert "api_key" in findings[0]["title"]
    assert findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_detect_secrets_empty_dir(tmp_path):
    """Test secret detection on empty directory."""
    results = await detect_secrets(str(tmp_path))
    assert results == []


@pytest.mark.asyncio
async def test_detect_secrets_with_secret(tmp_path):
    """Test secret detection finds hardcoded secrets."""
    # Create test file with a secret pattern
    # Using a generic test pattern that won't trigger real secret detection
    test_file = tmp_path / "config.py"
    test_file.write_text('API_KEY = "test_apikey_abcdefghijklmnopqrstuvwxyz"')

    results = await detect_secrets(str(tmp_path))

    assert len(results) >= 1
    assert any(r["type"] == "api_key" for r in results)
