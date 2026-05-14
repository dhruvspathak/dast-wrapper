from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.scan import Scan


class ResourceGovernance:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def ensure_scan_capacity(self, workspace_id: str = "default") -> None:
        result = await self.session.execute(
            select(func.count())
            .select_from(Scan)
            .where(Scan.workspace_id == workspace_id)
            .where(Scan.status.in_(["pending", "running"]))
        )
        active = int(result.scalar_one())
        if active >= settings.max_active_scans:
            raise RuntimeError(
                f"Workspace {workspace_id} has {active} active scans; limit is {settings.max_active_scans}"
            )

    async def request_cancellation(self, scan_id: str, workspace_id: str = "default") -> None:
        await self.session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .where(Scan.workspace_id == workspace_id)
            .where(Scan.status.in_(["pending", "running"]))
            .values(status="cancelling", cancellation_requested_at=datetime.utcnow())
        )

    async def cancellation_requested(self, scan_id: str) -> bool:
        result = await self.session.execute(select(Scan.status).where(Scan.id == scan_id))
        status = result.scalar_one_or_none()
        return status in {"cancelling", "cancelled"}
