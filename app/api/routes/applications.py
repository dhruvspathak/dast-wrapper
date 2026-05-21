from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.db.base import get_db
from app.schemas.platform import ApplicationCreate, ApplicationRead
from app.services.application_service import ApplicationService

router = APIRouter()


@router.post("", response_model=ApplicationRead)
async def create_application(payload: ApplicationCreate):
    async with get_db() as session:
        app = await ApplicationService(session).create(payload)
        return ApplicationRead(
            id=app.id,
            workspace_id=app.workspace_id,
            name=app.name,
            base_url=app.base_url,
            config=app.config,
        )


@router.get("/{application_id}", response_model=ApplicationRead)
async def get_application(application_id: str, workspace_id: str = "default"):
    async with get_db() as session:
        app = await ApplicationService(session).get(application_id, workspace_id)
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
        return ApplicationRead(
            id=app.id,
            workspace_id=app.workspace_id,
            name=app.name,
            base_url=app.base_url,
            config=app.config,
        )
