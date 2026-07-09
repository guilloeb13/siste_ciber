"""Analysis router for code and dependency scanning."""

import asyncio
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.finding import Finding, FindingSeverity, FindingStatus
from backend.app.models.user import User
from backend.app.ratelimit import limiter, scan_limit
from backend.app.routers.auth import get_current_user
from backend.app.security import (
    UploadTooLarge,
    ValidationError,
    resolve_within,
    safe_zip_members,
    sanitize_filename,
    stream_upload_to_path,
    validate_git_ref,
    validate_git_url,
)
from backend.app.services.database import get_db

router = APIRouter()


class ScanRequest(BaseModel):
    repo_path: str | None = None
    git_url: str | None = None
    branch: str = "main"
    scan_types: list[str] = ["bandit", "pip-audit", "secrets"]


class ScanResponse(BaseModel):
    scan_id: UUID
    status: str
    message: str
    started_at: datetime


class ScanResult(BaseModel):
    scan_id: UUID
    status: str
    findings_count: int
    by_severity: dict[str, int]
    duration_seconds: float
    completed_at: datetime


@router.post("/scan", response_model=ScanResponse)
@limiter.limit(scan_limit)
async def start_scan(
    request: Request,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """
    Start a security scan on a repository.

    Supports:
    - bandit: Python static analysis
    - pip-audit: Dependency vulnerability scanning
    - secrets: Secret detection in code
    - semgrep: Advanced pattern matching (if rules configured)
    """
    if not scan_request.repo_path and not scan_request.git_url:
        raise HTTPException(
            status_code=400,
            detail="Either repo_path or git_url must be provided"
        )

    # Validate untrusted inputs before they reach subprocess/filesystem calls.
    if scan_request.git_url:
        try:
            validate_git_url(scan_request.git_url)
            validate_git_ref(scan_request.branch)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    if scan_request.repo_path:
        # Local-path scanning is restricted to an operator-configured base
        # directory to prevent reading arbitrary files (e.g. /etc, secrets).
        if not settings.scan_base_dir:
            raise HTTPException(
                status_code=400,
                detail="Local path scanning is disabled (set SCAN_BASE_DIR to enable).",
            )
        try:
            resolved = resolve_within(settings.scan_base_dir, scan_request.repo_path)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        scan_request.repo_path = str(resolved)

    scan_id = uuid4()

    # Queue background scan task
    background_tasks.add_task(
        run_scan_task,
        scan_id=scan_id,
        repo_path=scan_request.repo_path,
        git_url=scan_request.git_url,
        branch=scan_request.branch,
        scan_types=scan_request.scan_types,
    )

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message="Scan has been queued for processing",
        started_at=datetime.utcnow(),
    )


async def run_scan_task(
    scan_id: UUID,
    repo_path: str | None,
    git_url: str | None,
    branch: str,
    scan_types: list[str],
):
    """Background task to run security scans."""
    from analysis.static_analysis import run_bandit_scan, run_pip_audit, detect_secrets, normalize_findings

    # Import db session for background task
    from backend.app.services.database import async_session

    target_path = repo_path

    # Clone if git URL provided. Inputs were validated by the request handler;
    # we still use an argument list (never a shell) and disable interactive
    # prompts / credential helpers so a malicious URL cannot inject commands.
    if git_url:
        try:
            validate_git_url(git_url)
            validate_git_ref(branch)
        except ValidationError:
            return
        target_path = tempfile.mkdtemp(prefix="navaja_scan_")
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"}
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--single-branch",
            "--branch", branch, "--", git_url, target_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        await proc.wait()
        if proc.returncode != 0:
            import shutil
            shutil.rmtree(target_path, ignore_errors=True)
            return

    if not target_path or not Path(target_path).exists():
        return

    findings = []

    try:
        # Run selected scans
        if "bandit" in scan_types:
            bandit_results = await run_bandit_scan(target_path)
            findings.extend(normalize_findings(bandit_results, "bandit", scan_id))

        if "pip-audit" in scan_types:
            pip_results = await run_pip_audit(target_path)
            findings.extend(normalize_findings(pip_results, "pip-audit", scan_id))

        if "secrets" in scan_types:
            secrets_results = await detect_secrets(target_path)
            findings.extend(normalize_findings(secrets_results, "secrets", scan_id))

        # Store findings in database
        async with async_session() as session:
            for finding_data in findings:
                finding = Finding(
                    scan_id=scan_id,
                    source=finding_data["source"],
                    rule_id=finding_data.get("rule_id"),
                    title=finding_data["title"],
                    description=finding_data.get("description"),
                    severity=FindingSeverity(finding_data["severity"]),
                    cvss_score=finding_data.get("cvss_score"),
                    status=FindingStatus.OPEN,
                    file_path=finding_data.get("file_path"),
                    line_number=finding_data.get("line_number"),
                    code_snippet=finding_data.get("code_snippet"),
                    recommendation=finding_data.get("recommendation"),
                    cwe_id=finding_data.get("cwe_id"),
                    cve_id=finding_data.get("cve_id"),
                )
                session.add(finding)
            await session.commit()

    except Exception as e:
        # Log error but don't raise in background task
        import structlog
        logger = structlog.get_logger()
        logger.error("scan_error", scan_id=str(scan_id), error=str(e))

    finally:
        # Cleanup temp directory if created
        if git_url and target_path:
            import shutil
            shutil.rmtree(target_path, ignore_errors=True)


@router.get("/scan/{scan_id}", response_model=dict)
async def get_scan_status(
    scan_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Get the status and results of a scan."""
    from sqlalchemy import select, func

    # Count findings for this scan
    result = await db.execute(
        select(func.count()).where(Finding.scan_id == scan_id)
    )
    total = result.scalar() or 0

    if total == 0:
        return {
            "scan_id": str(scan_id),
            "status": "pending",
            "findings_count": 0,
        }

    # Get severity breakdown
    by_severity = {}
    for sev in FindingSeverity:
        result = await db.execute(
            select(func.count())
            .where(Finding.scan_id == scan_id)
            .where(Finding.severity == sev)
        )
        count = result.scalar() or 0
        if count > 0:
            by_severity[sev.value] = count

    return {
        "scan_id": str(scan_id),
        "status": "completed",
        "findings_count": total,
        "by_severity": by_severity,
    }


@router.post("/upload", response_model=ScanResponse)
@limiter.limit(scan_limit)
async def upload_and_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    file: UploadFile = File(...),
    scan_types: str = "bandit,pip-audit,secrets",
):
    """
    Upload a zip file and scan its contents.

    Max file size: 500MB (configurable)
    """
    # Sanitize the client-supplied filename to a bare basename (no traversal).
    try:
        safe_name = sanitize_filename(file.filename or "upload.zip")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Stream the upload to disk with a hard size cap instead of buffering the
    # whole (up to hundreds of MB) file in memory.
    scan_id = uuid4()
    temp_dir = tempfile.mkdtemp(prefix=f"navaja_upload_{scan_id}_")
    zip_path = Path(temp_dir) / safe_name
    max_bytes = settings.max_repo_size_mb * 1024 * 1024

    try:
        info = await stream_upload_to_path(file, str(zip_path), max_bytes)
    except UploadTooLarge:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size: {settings.max_repo_size_mb}MB",
        )
    size_mb = info["size"] / (1024 * 1024)

    # Extract if zip, guarding against Zip Slip (path traversal) and zip bombs.
    extract_dir = Path(temp_dir) / "extracted"
    extract_dir.mkdir()

    if safe_name.endswith(".zip"):
        import zipfile
        # Allow the decompressed payload to be at most 4x the configured repo
        # limit, capping runaway expansion from a malicious archive.
        max_uncompressed = settings.max_repo_size_mb * 1024 * 1024 * 4
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                members = safe_zip_members(zf, str(extract_dir), max_uncompressed)
                for member in members:
                    zf.extract(member, extract_dir)
        except (ValidationError, zipfile.BadZipFile) as exc:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Invalid archive: {exc}")

    # Queue scan
    background_tasks.add_task(
        run_scan_task,
        scan_id=scan_id,
        repo_path=str(extract_dir),
        git_url=None,
        branch="main",
        scan_types=scan_types.split(","),
    )

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"File uploaded ({size_mb:.2f}MB) and scan queued",
        started_at=datetime.utcnow(),
    )
