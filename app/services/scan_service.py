from typing import List, Dict, Any
from app.db.base import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.application import Application
from app.services.governance import ResourceGovernance
from sqlalchemy import select, update
from app.workers.celery_app import celery_app
from app.workers.tasks import run_zap_scan

class ScanService:
    async def start_scan(self, config_id: str, workspace_id: str = "default") -> dict[str, str]:
        # Get application config
        async with get_db() as session:
            await ResourceGovernance(session).ensure_scan_capacity(workspace_id)
            app_result = await session.execute(
                select(Application).where(Application.id == config_id)
            )
            app = app_result.scalar_one_or_none()
            if not app:
                raise ValueError(f"Application {config_id} not found")
            
            # Create scan record with actual target
            scan = Scan(
                workspace_id=workspace_id,
                application_id=config_id,
                scanner="zap",
                config={"target": app.base_url},
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
        
        # Start Celery task
        task = run_zap_scan.delay(scan.id)
        async with get_db() as session:
            await session.execute(
                update(Scan).where(Scan.id == scan.id).values(celery_task_id=task.id)
            )
        return {"job_id": task.id, "scan_id": scan.id}

    async def cancel_scan(self, scan_id: str, workspace_id: str = "default") -> dict[str, str]:
        async with get_db() as session:
            await ResourceGovernance(session).request_cancellation(scan_id, workspace_id)
            result = await session.execute(select(Scan.celery_task_id).where(Scan.id == scan_id))
            celery_task_id = result.scalar_one_or_none()
            if celery_task_id:
                celery_app.control.revoke(celery_task_id, terminate=True)
        return {"scan_id": scan_id, "status": "cancellation_requested"}

    async def get_scan_status(self, job_id: str) -> Dict[str, Any]:
        # Check Celery task status
        result = celery_app.AsyncResult(job_id)
        async with get_db() as session:
            scan_result = await session.execute(select(Scan).where(Scan.celery_task_id == job_id))
            scan = scan_result.scalar_one_or_none()
            scan_payload = None
            if scan:
                scan_payload = {
                    "scan_id": scan.id,
                    "status": scan.status,
                    "scanner": scan.scanner,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "target": (scan.config or {}).get("target"),
                }
        if result.state == 'PENDING':
            return {"status": scan_payload["status"] if scan_payload else "pending", "scan": scan_payload}
        elif result.state == 'PROGRESS':
            return {"status": "running", "progress": result.info, "scan": scan_payload}
        elif result.state == 'SUCCESS':
            return {"status": "completed", "result": result.result, "scan": scan_payload}
        else:
            return {"status": "failed", "error": str(result.info), "scan": scan_payload}

    async def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        async with get_db() as session:
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )
            findings = result.scalars().all()
            return [
                {key: value for key, value in finding.__dict__.items() if not key.startswith("_")}
                for finding in findings
            ]
