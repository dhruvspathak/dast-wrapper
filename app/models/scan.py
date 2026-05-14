from sqlalchemy import DateTime, String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import uuid
from datetime import datetime

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    scanner: Mapped[str] = mapped_column(String(50), nullable=False)  # zap, nuclei, etc.
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    results: Mapped[dict] = mapped_column(JSON, nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    celery_task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    scanner_scan_id: Mapped[str] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    timeout_seconds: Mapped[int] = mapped_column(nullable=True)
    cancellation_requested_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)

    application = relationship("Application")
