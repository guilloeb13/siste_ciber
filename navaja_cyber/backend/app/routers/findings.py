"""Findings router for security analysis results."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.finding import Finding, FindingSeverity, FindingStatus
from backend.app.models.user import User, Role
from backend.app.routers.auth import get_current_user, require_role
from backend.app.services.database import get_db

router = APIRouter()


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    assigned_to: UUID | None = None
    false_positive_reason: str | None = None


class FindingResponse(BaseModel):
    id: UUID
    scan_id: UUID
    source: str
    rule_id: str | None
    title: str
    description: str | None
    severity: FindingSeverity
    cvss_score: int | None
    status: FindingStatus
    file_path: str | None
    line_number: int | None
    code_snippet: str | None
    recommendation: str | None
    cwe_id: str | None
    cve_id: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class FindingSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_source: dict[str, int]


@router.get("/", response_model=list[FindingResponse])
async def list_findings(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    scan_id: UUID | None = None,
    severity: FindingSeverity | None = None,
    status: FindingStatus | None = None,
    source: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List findings with filters."""
    query = select(Finding)

    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if source:
        query = query.where(Finding.source == source)

    query = query.order_by(Finding.severity.desc(), Finding.created_at.desc())
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/summary", response_model=FindingSummary)
async def get_findings_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    scan_id: UUID | None = None,
):
    """Get summary statistics for findings."""
    base_query = select(Finding)
    if scan_id:
        base_query = base_query.where(Finding.scan_id == scan_id)

    # Total count
    total_result = await db.execute(select(func.count()).select_from(base_query.subquery()))
    total = total_result.scalar() or 0

    # By severity
    by_severity = {}
    for sev in FindingSeverity:
        result = await db.execute(
            select(func.count())
            .select_from(base_query.where(Finding.severity == sev).subquery())
        )
        by_severity[sev.value] = result.scalar() or 0

    # By status
    by_status = {}
    for stat in FindingStatus:
        result = await db.execute(
            select(func.count())
            .select_from(base_query.where(Finding.status == stat).subquery())
        )
        by_status[stat.value] = result.scalar() or 0

    # By source
    source_result = await db.execute(
        select(Finding.source, func.count())
        .group_by(Finding.source)
    )
    by_source = {row[0]: row[1] for row in source_result}

    return FindingSummary(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_source=by_source,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Get a specific finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    update_data: FindingUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Update a finding status or assignment."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if update_data.status:
        finding.status = update_data.status
        if update_data.status == FindingStatus.RESOLVED:
            finding.resolved_at = datetime.utcnow()

    if update_data.assigned_to:
        finding.assigned_to = update_data.assigned_to

    if update_data.false_positive_reason:
        finding.false_positive_reason = update_data.false_positive_reason
        finding.status = FindingStatus.FALSE_POSITIVE

    finding.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(finding)

    return finding


@router.delete("/{finding_id}")
async def delete_finding(
    finding_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.ANALYST]))],
):
    """Delete a finding (admin/analyst only)."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    await db.delete(finding)
    await db.commit()

    return {"status": "deleted", "finding_id": str(finding_id)}
