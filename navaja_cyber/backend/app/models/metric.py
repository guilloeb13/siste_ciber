"""Metric model for storing monitoring data."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, Float, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from backend.app.services.database import Base


class MetricType(str, Enum):
    """Metric type enumeration."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    PROCESS = "process"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    FILE_INTEGRITY = "file_integrity"
    CUSTOM = "custom"


class Metric(Base):
    """Metric model for storing time-series monitoring data."""

    __tablename__ = "metrics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    metric_type = Column(SQLEnum(MetricType), nullable=False)
    name = Column(String(255), nullable=False)
    value = Column(Float, nullable=False)
    unit = Column(String(50))
    labels = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<Metric {self.metric_type}:{self.name}={self.value}>"
