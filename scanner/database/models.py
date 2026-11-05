import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_url = Column(String(512), nullable=False, index=True)
    repository_owner = Column(String(128), nullable=False, index=True)
    repository_name = Column(String(128), nullable=False, index=True)
    status = Column(
        String(32),
        nullable=False,
        default="queued",
        index=True,
    )  # queued, cloning, scanning, processing, completed, failed, cancelled
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    scan_version = Column(String(32), nullable=False, default="1.0.0")

    # Relationships
    findings = relationship(
        "FindingModel",
        back_populates="scan_job",
        cascade="all, delete-orphan",
        order_by="FindingModel.id",
    )
    summary = relationship(
        "ScanSummaryModel",
        back_populates="scan_job",
        uselist=False,
        cascade="all, delete-orphan",
    )


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(
        String(36),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, index=True)
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)

    # Relationships
    scan_job = relationship("ScanJobModel", back_populates="findings")
    evidence = relationship(
        "EvidenceModel",
        back_populates="finding",
        cascade="all, delete-orphan",
        order_by="EvidenceModel.id",
    )


class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(
        String(36),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    file_path = Column(String(512), nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=False)

    # Relationship
    finding = relationship("FindingModel", back_populates="evidence")


class ScanSummaryModel(Base):
    __tablename__ = "scan_summaries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(
        String(36),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    risk_score = Column(Float, nullable=False)
    risk_category = Column(String(32), nullable=False)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)
    scan_complete = Column(Boolean, nullable=False, default=True)

    # Relationship
    scan_job = relationship("ScanJobModel", back_populates="summary")

