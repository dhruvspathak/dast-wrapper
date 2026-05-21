from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.db.base import get_db
from app.graph.engine import GraphEngine
from app.models.authorization import (
    ApplicationMapSnapshot,
    AttackAttempt,
    AttackChain,
    AuthorizationGraphSnapshot,
    EvidenceRecord,
    ReasoningFinding,
    ScanJob,
    TrafficLog,
    ValidationResult,
    WorkflowTransition,
)
from app.orchestration.engine import OrchestrationEngine
from app.orchestration.queue import RedisWorkflowQueue
from app.schemas.platform import GraphRead, ScanJobRead, StartScanRequest
from app.workers.tasks import run_authorization_scan
from app.replay.lineage import LineageEngine

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


@router.get("/attack-chains/{attack_chain_id}")
async def get_attack_chain(attack_chain_id: str):
    async with get_db() as session:
        chain = await session.get(AttackChain, attack_chain_id)
        if not chain:
            raise HTTPException(status_code=404, detail="Attack chain not found")
        traffic = await LineageEngine(session).chain(attack_chain_id)
        evidence = list(
            (
                await session.execute(select(EvidenceRecord).where(EvidenceRecord.attack_chain_id == attack_chain_id))
            )
            .scalars()
            .all()
        )
        return {
            "chain": {
                "id": chain.id,
                "chain_type": chain.chain_type,
                "status": chain.status,
                "summary": chain.summary,
            },
            "timeline": [
                {
                    "traffic_log_id": item.id,
                    "parent_traffic_log_id": item.parent_traffic_log_id,
                    "source_type": item.source_type,
                    "replay_depth": item.replay_depth,
                    "method": item.request_method,
                    "url": item.request_url,
                    "status": item.response_status,
                    "created_at": item.created_at.isoformat(),
                }
                for item in traffic
            ],
            "evidence": [
                {
                    "id": item.id,
                    "evidence_type": item.evidence_type,
                    "confidence": item.confidence,
                    "normalized_diffs": item.normalized_diffs,
                    "validation_evidence": item.validation_evidence,
                }
                for item in evidence
            ],
        }


@router.get("/traffic/{traffic_log_id}/lineage")
async def get_traffic_lineage(traffic_log_id: str):
    async with get_db() as session:
        engine = LineageEngine(session)
        ancestors = await engine.ancestors(traffic_log_id)
        descendants = await engine.descendants(traffic_log_id)
        return {
            "traffic_log_id": traffic_log_id,
            "ancestors": [{"id": item.id, "url": item.request_url, "source_type": item.source_type} for item in ancestors],
            "descendants": [{"id": item.id, "url": item.request_url, "source_type": item.source_type} for item in descendants],
        }


@router.get("/scans/{scan_job_id}/workflow-timeline")
async def get_workflow_timeline(scan_job_id: str):
    async with get_db() as session:
        transitions = list(
            (
                await session.execute(
                    select(WorkflowTransition)
                    .where(WorkflowTransition.scan_job_id == scan_job_id)
                    .order_by(WorkflowTransition.created_at)
                )
            )
            .scalars()
            .all()
        )
        return {
            "transitions": [
                {
                    "id": item.id,
                    "from_state": item.from_state,
                    "to_state": item.to_state,
                    "action": item.transition_action,
                    "confidence": item.confidence,
                    "evidence": item.evidence,
                }
                for item in transitions
            ]
        }


@router.get("/scans/{scan_job_id}/graph-snapshots")
async def get_graph_snapshots(scan_job_id: str):
    async with get_db() as session:
        snapshots = list(
            (
                await session.execute(
                    select(AuthorizationGraphSnapshot)
                    .where(AuthorizationGraphSnapshot.scan_job_id == scan_job_id)
                    .order_by(AuthorizationGraphSnapshot.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        return {"snapshots": [{"id": item.id, "created_at": item.created_at.isoformat(), "graph": item.graph} for item in snapshots]}


@router.get("/scans/{scan_job_id}/application-map")
async def get_application_map(scan_job_id: str):
    async with get_db() as session:
        snapshot = (
            await session.execute(
                select(ApplicationMapSnapshot)
                .where(ApplicationMapSnapshot.scan_job_id == scan_job_id)
                .order_by(ApplicationMapSnapshot.created_at.desc())
            )
        ).scalar_one_or_none()
        if not snapshot:
            raise HTTPException(status_code=404, detail="Application map not found")
        return {"id": snapshot.id, "map": snapshot.map_data}


@router.get("/scans/{scan_job_id}/reasoning")
async def get_reasoning(scan_job_id: str):
    async with get_db() as session:
        findings = list(
            (
                await session.execute(
                    select(ReasoningFinding)
                    .where(ReasoningFinding.scan_job_id == scan_job_id)
                    .order_by(ReasoningFinding.confidence.desc())
                )
            )
            .scalars()
            .all()
        )
        return {
            "findings": [
                {
                    "id": item.id,
                    "finding_type": item.finding_type,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "explanation": item.explanation,
                    "evidence": item.evidence,
                }
                for item in findings
            ]
        }
