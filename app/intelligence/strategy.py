from __future__ import annotations

from dataclasses import asdict

from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.adaptive_planner import AdaptiveAttackPlan
from app.intelligence.application_mapper import ApplicationMap
from app.models.authorization import ScanStrategy


class ScanStrategyPlanner:
    def __init__(self, db: AsyncSession | None = None):
        self.db = db

    async def persist_strategy(
        self,
        *,
        workspace_id: str,
        application_id: str,
        scan_job_id: str | None,
        app_map: ApplicationMap,
        attack_plan: AdaptiveAttackPlan,
    ) -> dict:
        strategy = self.plan(app_map, attack_plan)
        if self.db:
            self.db.add(
                ScanStrategy(
                    workspace_id=workspace_id,
                    application_id=application_id,
                    scan_job_id=scan_job_id,
                    plan=strategy,
                    priority_score=strategy["priority_score"],
                )
            )
            await self.db.flush()
        return strategy

    def plan(self, app_map: ApplicationMap, attack_plan: AdaptiveAttackPlan) -> dict:
        prioritized_steps = attack_plan.prioritized()
        high_risk_entities = [
            name
            for name, entity in app_map.entities.items()
            if {"approve", "refund", "archive", "delete"} & set(entity.get("actions", []))
        ]
        return {
            "priority_score": round(sum(step.priority for step in prioritized_steps[:10]), 3),
            "high_risk_entities": high_risk_entities,
            "attack_steps": [asdict(step) for step in prioritized_steps],
            "noise_controls": {
                "dedupe_by_normalized_hash": True,
                "skip_static_resource_clusters": True,
                "prefer_high_ownership_confidence": True,
            },
        }
