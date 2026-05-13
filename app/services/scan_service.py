from typing import List, Dict, Any
import uuid
from app.db.base import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

class ScanService:
    async def start_scan(self, config_id: str) -> str:
        job_id = str(uuid.uuid4())
        # TODO: Start Celery task
        return job_id

    async def get_scan_status(self, job_id: str) -> Dict[str, Any]:
        # TODO: Check Celery task status
        return {"status": "running"}

    async def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        async with get_db() as session:
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )
            findings = result.scalars().all()
            return [finding.__dict__ for finding in findings]