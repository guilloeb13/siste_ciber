"""Metrics router for monitoring data."""

from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.agent import Agent
from backend.app.models.metric import Metric, MetricType
from backend.app.models.user import User
from backend.app.routers.agents import authenticate_agent
from backend.app.routers.auth import get_current_user
from backend.app.services.database import get_db

router = APIRouter()


class MetricCreate(BaseModel):
    # agent_id is optional and ignored on ingestion: metrics are attributed to
    # the authenticated agent, not to a client-supplied id (anti-spoofing).
    agent_id: UUID | None = None
    metric_type: MetricType
    name: str
    value: float
    unit: str | None = None
    labels: dict = {}
    timestamp: datetime | None = None


class MetricBatch(BaseModel):
    metrics: list[MetricCreate]


class MetricResponse(BaseModel):
    id: UUID
    agent_id: UUID
    metric_type: MetricType
    name: str
    value: float
    unit: str | None
    labels: dict
    timestamp: datetime

    class Config:
        from_attributes = True


class MetricSummary(BaseModel):
    agent_id: UUID
    metric_type: str
    avg_value: float
    min_value: float
    max_value: float
    count: int
    period_start: datetime
    period_end: datetime


@router.post("/", response_model=dict)
async def create_metric(
    metric_data: MetricCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent: Annotated[Agent, Depends(authenticate_agent)],
):
    """Record a single metric from an authenticated agent."""
    metric = Metric(
        agent_id=agent.id,
        metric_type=metric_data.metric_type,
        name=metric_data.name,
        value=metric_data.value,
        unit=metric_data.unit,
        labels=metric_data.labels,
        timestamp=metric_data.timestamp or datetime.utcnow(),
    )

    db.add(metric)
    await db.commit()

    return {"status": "ok", "metric_id": str(metric.id)}


# Cap batch size to bound memory/DB load from a single request.
MAX_BATCH_METRICS = 1000


@router.post("/batch", response_model=dict)
async def create_metrics_batch(
    batch: MetricBatch,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent: Annotated[Agent, Depends(authenticate_agent)],
):
    """Record multiple metrics from an authenticated agent in a single request."""
    if len(batch.metrics) > MAX_BATCH_METRICS:
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large (max {MAX_BATCH_METRICS} metrics)",
        )
    metrics = []
    for metric_data in batch.metrics:
        metric = Metric(
            agent_id=agent.id,
            metric_type=metric_data.metric_type,
            name=metric_data.name,
            value=metric_data.value,
            unit=metric_data.unit,
            labels=metric_data.labels,
            timestamp=metric_data.timestamp or datetime.utcnow(),
        )
        metrics.append(metric)

    db.add_all(metrics)
    await db.commit()

    return {"status": "ok", "count": len(metrics)}


@router.get("/", response_model=list[MetricResponse])
async def list_metrics(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    agent_id: UUID | None = None,
    metric_type: MetricType | None = None,
    hours: int = Query(default=1, ge=1, le=168),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List metrics with optional filters."""
    since = datetime.utcnow() - timedelta(hours=hours)

    query = select(Metric).where(Metric.timestamp >= since)

    if agent_id:
        query = query.where(Metric.agent_id == agent_id)
    if metric_type:
        query = query.where(Metric.metric_type == metric_type)

    query = query.order_by(Metric.timestamp.desc()).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/latest/{agent_id}", response_model=dict)
async def get_latest_metrics(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Get the latest metrics for an agent grouped by type."""
    # Get latest metric of each type for the agent
    latest_metrics = {}

    for metric_type in MetricType:
        result = await db.execute(
            select(Metric)
            .where(and_(Metric.agent_id == agent_id, Metric.metric_type == metric_type))
            .order_by(Metric.timestamp.desc())
            .limit(1)
        )
        metric = result.scalar_one_or_none()
        if metric:
            latest_metrics[metric_type.value] = {
                "name": metric.name,
                "value": metric.value,
                "unit": metric.unit,
                "timestamp": metric.timestamp.isoformat(),
            }

    return {
        "agent_id": str(agent_id),
        "metrics": latest_metrics,
        "retrieved_at": datetime.utcnow().isoformat(),
    }


@router.get("/alerts", response_model=list[dict])
async def get_metric_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    hours: int = Query(default=1, ge=1, le=24),
):
    """Get metrics that exceed alert thresholds."""
    since = datetime.utcnow() - timedelta(hours=hours)
    alerts = []

    # CPU > 90%
    result = await db.execute(
        select(Metric)
        .where(and_(
            Metric.metric_type == MetricType.CPU,
            Metric.value > 90,
            Metric.timestamp >= since
        ))
        .order_by(Metric.timestamp.desc())
    )
    for metric in result.scalars():
        alerts.append({
            "type": "cpu_high",
            "severity": "warning" if metric.value < 95 else "critical",
            "agent_id": str(metric.agent_id),
            "value": metric.value,
            "threshold": 90,
            "timestamp": metric.timestamp.isoformat(),
        })

    # Memory > 85%
    result = await db.execute(
        select(Metric)
        .where(and_(
            Metric.metric_type == MetricType.MEMORY,
            Metric.value > 85,
            Metric.timestamp >= since
        ))
        .order_by(Metric.timestamp.desc())
    )
    for metric in result.scalars():
        alerts.append({
            "type": "memory_high",
            "severity": "warning" if metric.value < 95 else "critical",
            "agent_id": str(metric.agent_id),
            "value": metric.value,
            "threshold": 85,
            "timestamp": metric.timestamp.isoformat(),
        })

    # Disk > 90%
    result = await db.execute(
        select(Metric)
        .where(and_(
            Metric.metric_type == MetricType.DISK,
            Metric.value > 90,
            Metric.timestamp >= since
        ))
        .order_by(Metric.timestamp.desc())
    )
    for metric in result.scalars():
        alerts.append({
            "type": "disk_high",
            "severity": "warning" if metric.value < 95 else "critical",
            "agent_id": str(metric.agent_id),
            "value": metric.value,
            "threshold": 90,
            "timestamp": metric.timestamp.isoformat(),
        })

    return sorted(alerts, key=lambda x: x["timestamp"], reverse=True)
