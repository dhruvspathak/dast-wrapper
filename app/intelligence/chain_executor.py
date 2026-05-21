from __future__ import annotations

from dataclasses import asdict

from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.adaptive_planner import AdaptiveAttackPlan, AdaptiveAttackStep
from app.models.authorization import AttackChain


class AttackChainExecutor:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def materialize_plan(
        self,
        *,
        workspace_id: str,
        application_id: str,
        scan_job_id: str,
        plan: AdaptiveAttackPlan,
        limit: int = 20,
    ) -> list[AttackChain]:
        chains = []
        for step in plan.prioritized()[:limit]:
            chains.append(
                await self.create_chain(
                    workspace_id=workspace_id,
                    application_id=application_id,
                    scan_job_id=scan_job_id,
                    step=step,
                )
            )
        return chains

    async def create_chain(
        self,
        *,
        workspace_id: str,
        application_id: str,
        scan_job_id: str,
        step: AdaptiveAttackStep,
    ) -> AttackChain:
        chain = AttackChain(
            workspace_id=workspace_id,
            application_id=application_id,
            scan_job_id=scan_job_id,
            chain_type=step.attack_type,
            status="planned",
            summary={"adaptive_step": asdict(step)},
        )
        self.db.add(chain)
        await self.db.flush()
        await self.db.refresh(chain)
        return chain
