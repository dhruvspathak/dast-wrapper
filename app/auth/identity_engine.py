from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import Identity, Session
from app.schemas.platform import IdentityCreate
from app.utils.security import encrypt_data


class IdentityEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_identity(
        self,
        application_id: str,
        payload: IdentityCreate,
        workspace_id: str = "default",
    ) -> Identity:
        encrypted_credentials = {}
        if payload.password:
            encrypted_credentials["password"] = encrypt_data(payload.password)
        identity = Identity(
            workspace_id=workspace_id,
            application_id=application_id,
            label=payload.label,
            role=payload.role,
            username=payload.username,
            encrypted_credentials=encrypted_credentials,
            login_config=payload.login_config.model_dump(mode="json"),
            auth_headers=payload.auth_headers,
        )
        self.db.add(identity)
        await self.db.flush()
        await self.db.refresh(identity)
        return identity

    async def list_identities(
        self,
        application_id: str,
        workspace_id: str = "default",
        identity_ids: list[str] | None = None,
    ) -> list[Identity]:
        query = select(Identity).where(
            Identity.application_id == application_id,
            Identity.workspace_id == workspace_id,
            Identity.is_active.is_(True),
        )
        if identity_ids:
            query = query.where(Identity.id.in_(identity_ids))
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def upsert_session(
        self,
        identity: Identity,
        *,
        cookies: dict[str, Any],
        local_storage: dict[str, Any],
        session_storage: dict[str, Any],
        auth_headers: dict[str, str],
        tokens: dict[str, Any],
        storage_state_path: str | None,
        traffic_history: list[dict[str, Any]] | None = None,
    ) -> Session:
        result = await self.db.execute(
            select(Session).where(
                Session.identity_id == identity.id,
                Session.application_id == identity.application_id,
            )
        )
        existing = result.scalar_one_or_none()
        values = {
            "status": "active",
            "cookies": cookies,
            "local_storage": local_storage,
            "session_storage": session_storage,
            "auth_headers": auth_headers,
            "tokens": tokens,
            "storage_state_path": storage_state_path,
            "traffic_history": traffic_history or [],
            "last_refreshed_at": datetime.utcnow(),
        }
        if existing:
            await self.db.execute(update(Session).where(Session.id == existing.id).values(**values))
            await self.db.flush()
            await self.db.refresh(existing)
            return existing

        session = Session(
            workspace_id=identity.workspace_id,
            application_id=identity.application_id,
            identity_id=identity.id,
            **values,
        )
        self.db.add(session)
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def get_active_session(self, identity_id: str) -> Session | None:
        result = await self.db.execute(
            select(Session).where(Session.identity_id == identity_id, Session.status == "active")
        )
        return result.scalar_one_or_none()
