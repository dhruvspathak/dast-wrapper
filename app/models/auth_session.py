from sqlalchemy import Boolean, String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import uuid
from datetime import datetime

class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    tokens: Mapped[dict] = mapped_column(JSON, nullable=False)  # backward compatible secure blob
    headers: Mapped[dict] = mapped_column(JSON, nullable=True)
    cookies: Mapped[dict] = mapped_column(JSON, nullable=True)
    local_storage: Mapped[dict] = mapped_column(JSON, nullable=True)
    session_storage: Mapped[dict] = mapped_column(JSON, nullable=True)
    refresh_token: Mapped[str] = mapped_column(String(2048), nullable=True)
    browser_storage_state_path: Mapped[str] = mapped_column(String(1024), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    application = relationship("Application")
