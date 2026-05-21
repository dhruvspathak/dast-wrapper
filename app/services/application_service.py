from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application import Application
from app.schemas.platform import ApplicationCreate


class ApplicationService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, payload: ApplicationCreate) -> Application:
        config = dict(payload.config)
        config.setdefault("application", {})
        config["application"].setdefault("name", payload.name)
        config["application"].setdefault("base_url", str(payload.base_url))
        app = Application(
            workspace_id=payload.workspace_id,
            name=payload.name,
            base_url=str(payload.base_url),
            config=config,
        )
        self.session.add(app)
        await self.session.flush()
        await self.session.refresh(app)
        return app

    async def get(self, application_id: str, workspace_id: str = "default") -> Application | None:
        result = await self.session.execute(
            select(Application).where(
                Application.id == application_id,
                Application.workspace_id == workspace_id,
            )
        )
        return result.scalar_one_or_none()
