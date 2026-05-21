from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth_session import AuthSession
from app.schemas.canonical import AuthContext, redact_secret_data

BROWSER_STATE_ROOT = Path("reports/browser-state")


class AuthContextManager:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_context(self, context: AuthContext) -> AuthSession:
        row = AuthSession(
            workspace_id=context.workspace_id,
            application_id=context.application_id,
            role=context.role,
            tokens=context.redacted(),
            headers=context.headers,
            cookies=context.cookies,
            local_storage=context.local_storage,
            session_storage=context.session_storage,
            refresh_token=context.refresh_token,
            browser_storage_state_path=context.browser_storage_state_path,
            expires_at=context.expires_at.replace(tzinfo=None) if context.expires_at else None,
            is_active=True,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def get_context(
        self,
        application_id: str,
        role: str,
        workspace_id: str = "default",
        include_expired: bool = False,
    ) -> AuthContext | None:
        result = await self.session.execute(
            select(AuthSession)
            .where(AuthSession.application_id == application_id)
            .where(AuthSession.workspace_id == workspace_id)
            .where(AuthSession.role == role)
            .where(AuthSession.is_active.is_(True))
            .order_by(AuthSession.created_at.desc())
        )
        row = result.scalars().first()
        if not row:
            return None

        context = self.from_row(row)
        if context.is_expired and not include_expired:
            return None
        return context

    async def list_contexts(
        self,
        application_id: str,
        workspace_id: str = "default",
        roles: Iterable[str] | None = None,
    ) -> list[AuthContext]:
        statement = (
            select(AuthSession)
            .where(AuthSession.application_id == application_id)
            .where(AuthSession.workspace_id == workspace_id)
            .where(AuthSession.is_active.is_(True))
            .order_by(AuthSession.role, AuthSession.created_at.desc())
        )
        if roles:
            statement = statement.where(AuthSession.role.in_(list(roles)))
        result = await self.session.execute(statement)
        contexts = [self.from_row(row) for row in result.scalars().all()]
        return [context for context in contexts if not context.is_expired]

    async def revoke_role(
        self,
        application_id: str,
        role: str,
        workspace_id: str = "default",
    ) -> None:
        await self.session.execute(
            update(AuthSession)
            .where(AuthSession.application_id == application_id)
            .where(AuthSession.workspace_id == workspace_id)
            .where(AuthSession.role == role)
            .values(is_active=False)
        )

    @staticmethod
    def from_row(row: AuthSession) -> AuthContext:
        token_blob = row.tokens or {}
        return AuthContext(
            id=row.id,
            workspace_id=row.workspace_id,
            application_id=row.application_id,
            role=row.role,
            headers=row.headers or token_blob.get("headers", {}),
            cookies=row.cookies or token_blob.get("cookies", {}),
            local_storage=row.local_storage or token_blob.get("local_storage", token_blob.get("localStorage", {})),
            session_storage=row.session_storage or token_blob.get("session_storage", token_blob.get("sessionStorage", {})),
            refresh_token=row.refresh_token or token_blob.get("refresh_token"),
            browser_storage_state_path=row.browser_storage_state_path or token_blob.get("browser_storage_state_path"),
            expires_at=row.expires_at,
            metadata=token_blob.get("metadata", {}),
        )

    @staticmethod
    def redacted_context(context: AuthContext) -> dict:
        return redact_secret_data(context.model_dump(mode="json"))


def session_state_path(workspace_id: str, application_id: str, role: str) -> str:
    safe_role = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in role)
    path = BROWSER_STATE_ROOT / workspace_id / application_id / f"{safe_role}.json"
    return str(path)
