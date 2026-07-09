"""Agents router for managing monitoring agents."""

import secrets
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.hashing import dummy_verify, hash_secret, verify_secret
from backend.app.models.agent import Agent, AgentStatus
from backend.app.models.user import User, Role
from backend.app.ratelimit import limiter, register_limit
from backend.app.routers.auth import get_current_user, require_role
from backend.app.services.database import get_db

router = APIRouter()


async def authenticate_agent(
    db: Annotated[AsyncSession, Depends(get_db)],
    x_agent_id: Annotated[str | None, Header()] = None,
    x_agent_token: Annotated[str | None, Header()] = None,
) -> Agent:
    """Authenticate an agent via its ID + bearer token headers.

    Metric and heartbeat ingestion must prove possession of the token issued at
    registration; otherwise anyone could inject fabricated telemetry for any
    agent. Returns the authenticated Agent or raises 401.
    """
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing agent credentials",
    )
    if not x_agent_id or not x_agent_token:
        raise invalid
    try:
        agent_uuid = UUID(x_agent_id)
    except (ValueError, TypeError):
        raise invalid

    result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
    agent = result.scalar_one_or_none()
    if agent is None or not agent.enabled:
        # Still run a verify to reduce agent-enumeration timing differences.
        dummy_verify()
        raise invalid
    if not verify_secret(agent.token_hash, x_agent_token):
        raise invalid
    return agent


class AgentRegister(BaseModel):
    name: str
    hostname: str
    ip_address: str
    os_type: str
    os_version: str | None = None
    agent_version: str
    tags: list[str] = []


class AgentResponse(BaseModel):
    id: UUID
    name: str
    hostname: str
    ip_address: str
    os_type: str
    status: AgentStatus
    last_seen: datetime
    tags: list

    class Config:
        from_attributes = True


class AgentRegistered(BaseModel):
    id: UUID
    token: str
    message: str


class AgentHeartbeat(BaseModel):
    status: AgentStatus = AgentStatus.ACTIVE


@router.post("/register", response_model=AgentRegistered)
@limiter.limit(register_limit)
async def register_agent(
    request: Request,
    agent_data: AgentRegister,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_enrollment_token: Annotated[str | None, Header()] = None,
):
    """Register a new monitoring agent and get authentication token.

    When AGENT_ENROLLMENT_TOKEN is configured, a matching X-Enrollment-Token
    header is required so that not just anyone can enroll an agent.
    """
    expected = settings.agent_enrollment_token
    if expected:
        if not x_enrollment_token or not secrets.compare_digest(
            x_enrollment_token, expected
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid enrollment token",
            )

    # Generate secure token
    token = secrets.token_urlsafe(32)
    token_hash = hash_secret(token)

    agent = Agent(
        name=agent_data.name,
        hostname=agent_data.hostname,
        ip_address=agent_data.ip_address,
        os_type=agent_data.os_type,
        os_version=agent_data.os_version,
        agent_version=agent_data.agent_version,
        token_hash=token_hash,
        status=AgentStatus.ACTIVE,
        tags=agent_data.tags,
    )

    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    return AgentRegistered(
        id=agent.id,
        token=token,
        message="Agent registered successfully. Store this token securely - it cannot be retrieved again."
    )


@router.get("/", response_model=list[AgentResponse])
async def list_agents(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    status: AgentStatus | None = None,
):
    """List all registered agents."""
    query = select(Agent).order_by(Agent.last_seen.desc())
    if status:
        query = query.where(Agent.status == status)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Get agent details."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return agent


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: UUID,
    heartbeat: AgentHeartbeat,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent: Annotated[Agent, Depends(authenticate_agent)],
):
    """Update agent heartbeat and status (authenticated agent only)."""
    # An agent may only update its own heartbeat.
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Agent id mismatch")

    await db.execute(
        update(Agent)
        .where(Agent.id == agent_id)
        .values(last_seen=datetime.utcnow(), status=heartbeat.status)
    )
    await db.commit()

    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN]))],
):
    """Delete an agent (admin only)."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    await db.delete(agent)
    await db.commit()

    return {"status": "deleted", "agent_id": str(agent_id)}
