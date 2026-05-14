from sqlalchemy import String, Text, ForeignKey, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import uuid
from datetime import datetime

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    scanner: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    scanner_finding_id: Mapped[str] = mapped_column(String(255), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    cwe: Mapped[str] = mapped_column(String(100), nullable=True)
    owasp: Mapped[str] = mapped_column(String(100), nullable=True)
    url: Mapped[str] = mapped_column(String(500), nullable=True)
    request: Mapped[dict] = mapped_column(JSON, nullable=True)
    response: Mapped[dict] = mapped_column(JSON, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, nullable=True)
    exploitability_score: Mapped[float] = mapped_column(Float, nullable=True)
    validation_status: Mapped[str] = mapped_column(String(50), default="pending")
    ai_analysis: Mapped[dict] = mapped_column(JSON, nullable=True)
    replay_results: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    scan = relationship("Scan")
