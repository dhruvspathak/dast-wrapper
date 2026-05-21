from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.db.base import get_db
from app.graph.engine import GraphEngine
from app.models.authorization import AttackAttempt, ScanJob, ValidationResult
from app.orchestration.engine import OrchestrationEngine
from app.orchestration.queue import RedisWorkflowQueue
from app.schemas.platform import GraphRead, ScanJobRead, StartScanRequest
from app.workers.tasks import run_authorization_scan

router = APIRouter()


@router.post("/scans", response_model=ScanJobRead)
async def start_authorization_scan(payload: StartScanRequest):
    async with get_db() as session:
        job = await OrchestrationEngine(session).create_scan_job(
            application_id=payload.application_id,
            workspace_id=payload.workspace_id,
            scanner_backend=payload.scanner_backend,
            identity_ids=payload.identity_ids,
            config=payload.config,
        )
        await RedisWorkflowQueue().enqueue(
            "authorization_scan",
            {"scan_job_id": job.id},
            idempotency_key=f"authorization_scan:{job.id}",
        )
        run_authorization_scan.delay(job.id)
        return ScanJobRead(
            id=job.id,
            application_id=job.application_id,
            status=job.status,
            scanner_backend=job.scanner_backend,
            current_stage=job.current_stage,
            results=job.results,
            error=job.error,
        )


@router.get("/scans/{scan_job_id}", response_model=ScanJobRead)
async def get_authorization_scan(scan_job_id: str):
    async with get_db() as session:
        job = await session.get(ScanJob, scan_job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found")
        return ScanJobRead(
            id=job.id,
            application_id=job.application_id,
            status=job.status,
            scanner_backend=job.scanner_backend,
            current_stage=job.current_stage,
            results=job.results,
            error=job.error,
        )


@router.get("/scans/{scan_job_id}/findings")
async def get_authorization_findings(scan_job_id: str):
    async with get_db() as session:
        result = await session.execute(
            select(AttackAttempt, ValidationResult)
            .join(ValidationResult, ValidationResult.attack_attempt_id == AttackAttempt.id)
            .where(AttackAttempt.scan_job_id == scan_job_id)
        )
        findings = []
        for attempt, validation in result.all():
            if validation.verdict not in {"confirmed", "likely", "needs_review"}:
                continue
            findings.append(
                {
                    "id": attempt.id,
                    "title": f"{attempt.attack_type} via cross-identity replay",
                    "severity": "high" if validation.verdict == "confirmed" else "medium",
                    "validation_status": validation.verdict,
                    "exploitability_score": validation.confidence,
                    "source_identity_id": attempt.source_identity_id,
                    "target_identity_id": attempt.target_identity_id,
                    "evidence": {
                        "request": attempt.replay_request,
                        "response": attempt.replay_response,
                        "validation": validation.evidence,
                    },
                }
            )
        return {"findings": findings}


@router.get("/applications/{application_id}/graph", response_model=GraphRead)
async def get_authorization_graph(application_id: str, scan_job_id: str | None = None):
    async with get_db() as session:
        graph = await GraphEngine(session).build_graph(application_id, scan_job_id)
        return GraphRead(application_id=application_id, scan_job_id=scan_job_id, graph=graph)
