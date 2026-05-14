from sqlalchemy import String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import uuid
from datetime import datetime

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)  # HTML or structured data
    artifact_type: Mapped[str] = mapped_column(String(50), default="json")
    path: Mapped[str] = mapped_column(String(1024), nullable=True)
    checksum: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    scan = relationship("Scan")
