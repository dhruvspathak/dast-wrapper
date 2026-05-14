from datetime import datetime
import uuid

from sqlalchemy import Float, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ReplayValidation(Base):
    __tablename__ = "replay_validations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    auth_session_id: Mapped[str] = mapped_column(String(36), ForeignKey("auth_sessions.id"), nullable=True)
    role: Mapped[str] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    validator: Mapped[str] = mapped_column(String(100), nullable=False)
    request: Mapped[dict] = mapped_column(JSON, nullable=False)
    baseline_response: Mapped[dict] = mapped_column(JSON, nullable=True)
    replay_response: Mapped[dict] = mapped_column(JSON, nullable=True)
    diff: Mapped[dict] = mapped_column(JSON, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)

    finding = relationship("Finding")
