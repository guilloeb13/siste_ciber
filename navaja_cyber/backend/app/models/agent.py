"""Agent model for monitoring agents."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID

from backend.app.services.database import Base


class AgentStatus(str, Enum):
    """Agent status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISCONNECTED = "disconnected"
    MAINTENANCE = "maintenance"


class Agent(Base):
    """Agent model for monitoring agents deployed on servers."""

    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)
    os_type = Column(String(50), nullable=False)  # linux, windows
    os_version = Column(String(100))
    agent_version = Column(String(20), nullable=False)
    status = Column(SQLEnum(AgentStatus), default=AgentStatus.INACTIVE)
    token_hash = Column(String(255), nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    config = Column(JSON, default=dict)
    tags = Column(JSON, default=list)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Agent {self.name} ({self.hostname})>"
