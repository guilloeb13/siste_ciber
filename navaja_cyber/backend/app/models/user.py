"""User model for authentication and RBAC."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID

from backend.app.services.database import Base


class Role(str, Enum):
    """User role enumeration for RBAC."""
    ADMIN = "admin"
    ANALYST = "analyst"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    TRAINER = "trainer"


class User(Base):
    """User model for authentication."""

    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(Role), default=Role.ANALYST)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    permissions = Column(JSON, default=list)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
