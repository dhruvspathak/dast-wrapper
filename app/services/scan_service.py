from typing import List, Dict, Any
from app.db.base import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.application import Application
from sqlalchemy import select
from app.workers.celery_app import celery_app
from app.workers.tasks import run_zap_scan

class ScanService:
    async def start_scan(self, config_id: str) -> str:
        # Get application config
        async with get_db() as session:
            app_result = await session.execute(
                select(Application).where(Application.id == config_id)
            )
            app = app_result.scalar_one_or_none()
            if not app:
                raise ValueError(f"Application {config_id} not found")
            
            # Create scan record with actual target
            scan = Scan(
                application_id=config_id,
                scanner="zap",
                config={"target": app.base_url}
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
        
        # Start Celery task
        task = run_zap_scan.delay(scan.id)
        return task.id

    async def get_scan_status(self, job_id: str) -> Dict[str, Any]:
        # Check Celery task status
        result = celery_app.AsyncResult(job_id)
        if result.state == 'PENDING':
            return {"status": "pending"}
        elif result.state == 'PROGRESS':
            return {"status": "running", "progress": result.info}
        elif result.state == 'SUCCESS':
            return {"status": "completed", "result": result.result}
        else:
            return {"status": "failed", "error": str(result.info)}

    async def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        async with get_db() as session:
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )
            findings = result.scalars().all()
            return [finding.__dict__ for finding in findings]
