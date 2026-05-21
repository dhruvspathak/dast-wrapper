from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import AttackChain, TrafficLog


class LineageEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_attack_chain(
        self,
        *,
        workspace_id: str,
        application_id: str,
        scan_job_id: str,
        chain_type: str,
        root_traffic_log_id: str | None,
        summary: dict | None = None,
    ) -> AttackChain:
        chain = AttackChain(
            workspace_id=workspace_id,
            application_id=application_id,
            scan_job_id=scan_job_id,
            chain_type=chain_type,
            root_traffic_log_id=root_traffic_log_id,
            summary=summary or {},
        )
        self.db.add(chain)
        await self.db.flush()
        await self.db.refresh(chain)
        return chain

    async def ancestors(self, traffic_log_id: str) -> list[TrafficLog]:
        current = await self.db.get(TrafficLog, traffic_log_id)
        lineage: list[TrafficLog] = []
        while current and current.parent_traffic_log_id:
            parent = await self.db.get(TrafficLog, current.parent_traffic_log_id)
            if not parent:
                break
            lineage.append(parent)
            current = parent
        return lineage

    async def descendants(self, traffic_log_id: str) -> list[TrafficLog]:
        result = await self.db.execute(
            select(TrafficLog).where(TrafficLog.parent_traffic_log_id == traffic_log_id)
        )
        direct = list(result.scalars().all())
        descendants = list(direct)
        for child in direct:
            descendants.extend(await self.descendants(child.id))
        return descendants

    async def chain(self, attack_chain_id: str) -> list[TrafficLog]:
        result = await self.db.execute(
            select(TrafficLog)
            .where(TrafficLog.attack_chain_id == attack_chain_id)
            .order_by(TrafficLog.replay_depth, TrafficLog.created_at)
        )
        return list(result.scalars().all())
