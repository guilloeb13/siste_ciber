"""CTF models for training challenges."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, Text, JSON, Integer, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from backend.app.services.database import Base


class ChallengeCategory(str, Enum):
    """Challenge category enumeration."""
    WEB = "web"
    FORENSIC = "forensic"
    CRYPTO = "crypto"
    MISC = "misc"
    NETWORK = "network"
    BINARY = "binary"
    CONFIG = "configuration"


class ChallengeStatus(str, Enum):
    """Challenge status enumeration."""
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class CTFEvent(Base):
    """CTF Event container."""

    __tablename__ = "ctf_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    is_active = Column(Boolean, default=False)
    config = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class Challenge(Base):
    """CTF Challenge model."""

    __tablename__ = "challenges"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("ctf_events.id"))
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(SQLEnum(ChallengeCategory), nullable=False)
    points = Column(Integer, nullable=False)
    flag_hash = Column(String(255), nullable=False)
    docker_image = Column(String(500))
    docker_config = Column(JSON, default=dict)
    hints = Column(JSON, default=list)
    files = Column(JSON, default=list)
    status = Column(SQLEnum(ChallengeStatus), default=ChallengeStatus.DRAFT)
    solves = Column(Integer, default=0)
    max_attempts = Column(Integer, default=0)  # 0 = unlimited
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Challenge {self.name} ({self.category})>"


class Team(Base):
    """CTF Team model."""

    __tablename__ = "teams"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("ctf_events.id"))
    name = Column(String(255), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    score = Column(Integer, default=0)
    members = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Team {self.name} (score: {self.score})>"


class Submission(Base):
    """CTF Flag submission model."""

    __tablename__ = "submissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    team_id = Column(UUID(as_uuid=True), ForeignKey("teams.id"), nullable=False)
    challenge_id = Column(UUID(as_uuid=True), ForeignKey("challenges.id"), nullable=False)
    flag_submitted = Column(String(500), nullable=False)
    is_correct = Column(Boolean, nullable=False)
    points_awarded = Column(Integer, default=0)
    submitted_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Submission team={self.team_id} correct={self.is_correct}>"
