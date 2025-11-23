"""Agents router for managing monitoring agents."""

import secrets
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.agent import Agent, AgentStatus
from backend.app.models.user import User, Role
from backend.app.routers.auth import get_current_user, require_role
from backend.app.services.database import get_db

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
async def register_agent(
    agent_data: AgentRegister,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Register a new monitoring agent and get authentication token."""
    # Generate secure token
    token = secrets.token_urlsafe(32)
    token_hash = pwd_context.hash(token)

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
):
    """Update agent heartbeat and status."""
    result = await db.execute(
        update(Agent)
        .where(Agent.id == agent_id)
        .values(last_seen=datetime.utcnow(), status=heartbeat.status)
        .returning(Agent.id)
    )

    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not found")

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
