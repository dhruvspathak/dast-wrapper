from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.auth.identity_engine import IdentityEngine
from app.db.base import get_db
from app.schemas.platform import IdentityCreate, IdentityRead
from app.services.application_service import ApplicationService

router = APIRouter()


@router.post("/applications/{application_id}/identities", response_model=IdentityRead)
async def add_identity(application_id: str, payload: IdentityCreate, workspace_id: str = "default"):
    async with get_db() as session:
        app = await ApplicationService(session).get(application_id, workspace_id)
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
        identity = await IdentityEngine(session).add_identity(application_id, payload, workspace_id)
        return IdentityRead(
            id=identity.id,
            application_id=identity.application_id,
            label=identity.label,
            role=identity.role,
            username=identity.username,
            is_active=identity.is_active,
        )


@router.get("/applications/{application_id}/identities", response_model=list[IdentityRead])
async def list_identities(application_id: str, workspace_id: str = "default"):
    async with get_db() as session:
        identities = await IdentityEngine(session).list_identities(application_id, workspace_id)
        return [
            IdentityRead(
                id=identity.id,
                application_id=identity.application_id,
                label=identity.label,
                role=identity.role,
                username=identity.username,
                is_active=identity.is_active,
            )
            for identity in identities
        ]
