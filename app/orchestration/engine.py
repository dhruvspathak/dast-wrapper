from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.attack_engine.engine import AuthorizationAttackEngine
from app.auth.authentication_engine import AuthenticationIntelligenceEngine
from app.auth.identity_engine import IdentityEngine
from app.crawling.engine import AuthenticatedCrawler
from app.crawling.object_discovery import ObjectDiscoveryEngine
from app.graph.engine import GraphEngine
from app.models.application import Application
from app.models.authorization import Identity, ScanJob, WorkflowState
from app.scanners.adapter import get_scanner_adapter
from app.storage.traffic_store import TrafficStore


class OrchestrationEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan_job(
        self,
        application_id: str,
        workspace_id: str = "default",
        scanner_backend: str = "zap",
        identity_ids: list[str] | None = None,
        config: dict | None = None,
    ) -> ScanJob:
        job = ScanJob(
            workspace_id=workspace_id,
            application_id=application_id,
            scanner_backend=scanner_backend,
            config={**(config or {}), "identity_ids": identity_ids or []},
            status="queued",
        )
        self.db.add(job)
        await self.db.flush()
        state = WorkflowState(
            workspace_id=workspace_id,
            scan_job_id=job.id,
            workflow_name="authorization_scan",
            idempotency_key=f"authorization_scan:{job.id}",
            status="queued",
            stage="queued",
            payload={"application_id": application_id, "identity_ids": identity_ids or []},
        )
        self.db.add(state)
        await self.db.flush()
        await self.db.refresh(job)
        return job

    async def run_authorization_scan(self, scan_job_id: str) -> ScanJob:
        job = await self._load_job(scan_job_id)
        application = await self.db.get(Application, job.application_id)
        if not application:
            raise RuntimeError(f"Application {job.application_id} not found")

        await self._mark(job, "running", "authenticating", started_at=datetime.utcnow())
        identity_engine = IdentityEngine(self.db)
        identities = await identity_engine.list_identities(
            application.id,
            job.workspace_id,
            identity_ids=(job.config or {}).get("identity_ids") or None,
        )
        if len(identities) < 2:
            raise RuntimeError("Authorization testing requires at least two active identities")

        auth_engine = AuthenticationIntelligenceEngine(identity_engine)
        sessions = []
        for identity in identities:
            sessions.append(await auth_engine.authenticate(application, identity))

        await self._mark(job, "running", "crawling")
        crawler = AuthenticatedCrawler(TrafficStore(self.db), max_pages=int((job.config or {}).get("max_pages", 50)))
        for identity, session in zip(identities, sessions):
            await crawler.crawl(application, job, identity, session)

        await self._mark(job, "running", "object_discovery")
        objects = await ObjectDiscoveryEngine(self.db).discover_for_scan(job.id)

        await self._mark(job, "running", "scanner_context")
        scanner = get_scanner_adapter(job.scanner_backend)
        await scanner.inject_context(application=application, identities=identities, sessions=sessions)
        scanner_scan_id = await scanner.start_scan(application.base_url)

        await self._mark(job, "running", "authorization_attacks")
        attempts = await AuthorizationAttackEngine(self.db).run_attacks(job.id, application.id)

        await self._mark(job, "running", "graph")
        graph = await GraphEngine(self.db).build_graph(application.id, job.id)

        await self._mark(
            job,
            "completed",
            "completed",
            completed_at=datetime.utcnow(),
            results={
                "identities": len(identities),
                "sessions": len(sessions),
                "objects": len(objects),
                "attack_attempts": len(attempts),
                "scanner_scan_id": scanner_scan_id,
                "graph_nodes": len(graph.get("nodes", [])),
            },
        )
        return job

    async def _load_job(self, scan_job_id: str) -> ScanJob:
        result = await self.db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
        job = result.scalar_one_or_none()
        if not job:
            raise RuntimeError(f"Scan job {scan_job_id} not found")
        return job

    async def _mark(self, job: ScanJob, status: str, stage: str, **extra) -> None:
        values = {"status": status, "current_stage": stage, "updated_at": datetime.utcnow(), **extra}
        await self.db.execute(update(ScanJob).where(ScanJob.id == job.id).values(**values))
        await self.db.execute(
            update(WorkflowState)
            .where(WorkflowState.scan_job_id == job.id)
            .values(status=status, stage=stage, updated_at=datetime.utcnow())
        )
        await self.db.flush()
        for key, value in values.items():
            setattr(job, key, value)
