"""Analysis router for code and dependency scanning."""

import asyncio
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.finding import Finding, FindingSeverity, FindingStatus
from backend.app.models.user import User
from backend.app.routers.auth import get_current_user
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
async def start_scan(
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

    # Clone if git URL provided
    if git_url:
        target_path = tempfile.mkdtemp(prefix="navaja_scan_")
        clone_cmd = f"git clone --depth 1 --branch {branch} {git_url} {target_path}"
        proc = await asyncio.create_subprocess_shell(
            clone_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()

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
async def upload_and_scan(
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
    # Check file size
    content = await file.read()
    size_mb = len(content) / (1024 * 1024)

    if size_mb > settings.max_repo_size_mb:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max size: {settings.max_repo_size_mb}MB"
        )

    # Save to temp file
    scan_id = uuid4()
    temp_dir = tempfile.mkdtemp(prefix=f"navaja_upload_{scan_id}_")
    zip_path = Path(temp_dir) / file.filename

    with open(zip_path, "wb") as f:
        f.write(content)

    # Extract if zip
    extract_dir = Path(temp_dir) / "extracted"
    extract_dir.mkdir()

    if file.filename.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)

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
