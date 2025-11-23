"""
Static Analysis Module

Wrappers for security scanning tools: Bandit, pip-audit, secret detection.

USO AUTORIZADO ÚNICAMENTE. Este módulo analiza código para detectar vulnerabilidades.
No genera exploits ni código malicioso.
"""

import asyncio
import json
import re
import tempfile
from pathlib import Path
from uuid import UUID

import structlog

logger = structlog.get_logger(__name__)


async def run_bandit_scan(target_path: str) -> list[dict]:
    """
    Run Bandit static analysis on Python code.

    Bandit is a tool designed to find common security issues in Python code.
    """
    results = []

    try:
        # Run bandit with JSON output
        proc = await asyncio.create_subprocess_exec(
            "bandit",
            "-r",
            "-f", "json",
            "-ll",  # Only medium and above
            target_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if stdout:
            data = json.loads(stdout.decode())
            results = data.get("results", [])

        logger.info("bandit_scan_complete", issues_found=len(results), path=target_path)

    except FileNotFoundError:
        logger.warning("bandit_not_installed", message="Install with: pip install bandit")
    except json.JSONDecodeError as e:
        logger.error("bandit_parse_error", error=str(e))
    except Exception as e:
        logger.error("bandit_scan_error", error=str(e))

    return results


async def run_pip_audit(target_path: str) -> list[dict]:
    """
    Run pip-audit to check for vulnerable dependencies.

    Scans requirements.txt or pyproject.toml for known vulnerabilities.
    """
    results = []

    # Find requirements file
    requirements_files = [
        Path(target_path) / "requirements.txt",
        Path(target_path) / "pyproject.toml",
        Path(target_path) / "setup.py",
    ]

    requirements_file = None
    for rf in requirements_files:
        if rf.exists():
            requirements_file = rf
            break

    if not requirements_file:
        logger.info("pip_audit_skip", reason="no_requirements_file")
        return results

    try:
        # Run pip-audit
        cmd = ["pip-audit", "--format", "json"]

        if requirements_file.name == "requirements.txt":
            cmd.extend(["-r", str(requirements_file)])
        else:
            cmd.append(str(target_path))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=target_path,
        )

        stdout, stderr = await proc.communicate()

        if stdout:
            data = json.loads(stdout.decode())
            dependencies = data.get("dependencies", [])

            for dep in dependencies:
                for vuln in dep.get("vulns", []):
                    results.append({
                        "package": dep["name"],
                        "version": dep["version"],
                        "vuln_id": vuln.get("id"),
                        "fix_versions": vuln.get("fix_versions", []),
                        "description": vuln.get("description", ""),
                    })

        logger.info("pip_audit_complete", vulnerabilities=len(results))

    except FileNotFoundError:
        logger.warning("pip_audit_not_installed", message="Install with: pip install pip-audit")
    except json.JSONDecodeError as e:
        logger.error("pip_audit_parse_error", error=str(e))
    except Exception as e:
        logger.error("pip_audit_error", error=str(e))

    return results


async def detect_secrets(target_path: str) -> list[dict]:
    """
    Detect secrets and sensitive data in code.

    Searches for patterns like API keys, passwords, tokens.
    This is a simple implementation - for production use gitleaks or similar.
    """
    results = []

    # Secret patterns (non-exploitative detection only)
    patterns = [
        (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "api_key"),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "password"),
        (r"(?i)(secret|token)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "secret"),
        (r"(?i)(aws_access_key_id)\s*[=:]\s*['\"]?(AKIA[A-Z0-9]{16})['\"]?", "aws_key"),
        (r"(?i)(aws_secret_access_key)\s*[=:]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?", "aws_secret"),
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key"),
        (r"(?i)(bearer|authorization)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", "bearer_token"),
    ]

    # File extensions to scan
    scannable_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
        ".env", ".conf", ".config", ".ini", ".sh", ".bash", ".go", ".java",
    }

    try:
        path = Path(target_path)

        for file_path in path.rglob("*"):
            # Skip non-files and large files
            if not file_path.is_file():
                continue
            if file_path.stat().st_size > 1_000_000:  # 1MB limit
                continue
            if file_path.suffix not in scannable_extensions:
                continue

            # Skip common false positive directories
            if any(p in str(file_path) for p in ["node_modules", ".git", "__pycache__", "venv"]):
                continue

            try:
                content = file_path.read_text(errors="ignore")
                lines = content.split("\n")

                for line_num, line in enumerate(lines, 1):
                    for pattern, secret_type in patterns:
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            # Don't capture the actual secret value
                            results.append({
                                "file": str(file_path.relative_to(path)),
                                "line": line_num,
                                "type": secret_type,
                                "pattern": pattern[:50] + "...",
                                "snippet": line[:100] + "..." if len(line) > 100 else line,
                            })

            except Exception as e:
                logger.debug("file_scan_error", file=str(file_path), error=str(e))

        logger.info("secret_scan_complete", secrets_found=len(results))

    except Exception as e:
        logger.error("secret_detection_error", error=str(e))

    return results


def normalize_findings(raw_results: list[dict], source: str, scan_id: UUID) -> list[dict]:
    """
    Normalize findings from different scanners to a common format.

    Maps tool-specific output to the Finding model structure.
    """
    findings = []

    for result in raw_results:
        finding = {
            "scan_id": str(scan_id),
            "source": source,
        }

        if source == "bandit":
            # Map Bandit severity
            severity_map = {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            }

            finding.update({
                "rule_id": result.get("test_id"),
                "title": result.get("test_name", "Unknown Issue"),
                "description": result.get("issue_text"),
                "severity": severity_map.get(result.get("issue_severity"), "medium"),
                "cvss_score": 70 if result.get("issue_severity") == "HIGH" else 50,
                "file_path": result.get("filename"),
                "line_number": result.get("line_number"),
                "code_snippet": result.get("code"),
                "cwe_id": result.get("issue_cwe", {}).get("id"),
                "recommendation": f"Review and fix {result.get('test_name')}. See: {result.get('more_info', '')}",
            })

        elif source == "pip-audit":
            finding.update({
                "rule_id": result.get("vuln_id"),
                "title": f"Vulnerable dependency: {result.get('package')} {result.get('version')}",
                "description": result.get("description"),
                "severity": "high",  # Dependencies with known vulns are high severity
                "cvss_score": 70,
                "cve_id": result.get("vuln_id") if result.get("vuln_id", "").startswith("CVE") else None,
                "recommendation": f"Upgrade {result.get('package')} to one of: {', '.join(result.get('fix_versions', ['latest']))}",
            })

        elif source == "secrets":
            finding.update({
                "rule_id": f"SECRET_{result.get('type', 'unknown').upper()}",
                "title": f"Potential secret detected: {result.get('type')}",
                "description": f"A potential {result.get('type')} was found in the code.",
                "severity": "high",
                "cvss_score": 80,
                "file_path": result.get("file"),
                "line_number": result.get("line"),
                "code_snippet": result.get("snippet"),
                "recommendation": "Remove secret from code and use environment variables or a secret manager.",
            })

        findings.append(finding)

    return findings


async def run_semgrep(target_path: str, rules_path: str | None = None) -> list[dict]:
    """
    Run Semgrep for advanced pattern matching (optional).

    Requires semgrep to be installed: pip install semgrep
    """
    results = []

    try:
        cmd = ["semgrep", "--json"]

        if rules_path:
            cmd.extend(["--config", rules_path])
        else:
            cmd.extend(["--config", "auto"])

        cmd.append(target_path)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if stdout:
            data = json.loads(stdout.decode())
            results = data.get("results", [])

        logger.info("semgrep_scan_complete", issues_found=len(results))

    except FileNotFoundError:
        logger.info("semgrep_not_installed", message="Optional: pip install semgrep")
    except Exception as e:
        logger.error("semgrep_error", error=str(e))

    return results


# CLI interface
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python static_analysis.py <path>")
        sys.exit(1)

    target = sys.argv[1]

    async def main():
        from uuid import uuid4

        scan_id = uuid4()
        print(f"Scanning: {target}")
        print(f"Scan ID: {scan_id}")
        print("-" * 50)

        # Run scans
        bandit_results = await run_bandit_scan(target)
        pip_results = await run_pip_audit(target)
        secret_results = await detect_secrets(target)

        # Normalize
        all_findings = []
        all_findings.extend(normalize_findings(bandit_results, "bandit", scan_id))
        all_findings.extend(normalize_findings(pip_results, "pip-audit", scan_id))
        all_findings.extend(normalize_findings(secret_results, "secrets", scan_id))

        # Print summary
        print(f"\nTotal findings: {len(all_findings)}")

        by_severity = {}
        for f in all_findings:
            sev = f.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        print("\nBy severity:")
        for sev, count in sorted(by_severity.items()):
            print(f"  {sev}: {count}")

        # Print findings
        print("\nFindings:")
        for f in all_findings:
            print(f"\n[{f['severity'].upper()}] {f['title']}")
            if f.get('file_path'):
                print(f"  File: {f['file_path']}:{f.get('line_number', '?')}")
            if f.get('recommendation'):
                print(f"  Fix: {f['recommendation']}")

    asyncio.run(main())
