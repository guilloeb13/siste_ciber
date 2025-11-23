"""Finding model for security analysis results."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, Text, JSON, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID

from backend.app.services.database import Base


class FindingSeverity(str, Enum):
    """Finding severity levels based on CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status enumeration."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Finding(Base):
    """Security finding from analysis modules."""

    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    source = Column(String(50), nullable=False)  # bandit, semgrep, pip-audit, etc.
    rule_id = Column(String(100))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(FindingSeverity), nullable=False)
    cvss_score = Column(Integer)  # 0-100
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN)
    file_path = Column(String(1000))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    recommendation = Column(Text)
    cwe_id = Column(String(20))
    cve_id = Column(String(50))
    references = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)
    false_positive_reason = Column(Text)
    assigned_to = Column(UUID(as_uuid=True))
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Finding {self.severity}:{self.title[:50]}>"
