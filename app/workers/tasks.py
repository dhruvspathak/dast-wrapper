from app.workers.celery_app import celery_app
from app.scanners.base import ScanTarget
from app.scanners.registry import scanner_registry
from app.replay.replay_engine import ReplayEngine
from app.validators.idor_validator import IDORValidator
import asyncio
from app.db.base import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.application import Application
from app.core.config import settings
from sqlalchemy import select, update
import time
import logging

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="run_zap_scan")
def run_zap_scan(self, scan_id):
    # Run this in a new event loop since Celery runs in a separate thread
    return asyncio.run(_run_zap_scan_async(self, scan_id))

async def _run_zap_scan_async(self, scan_id):
    try:
        return await _execute_zap_scan(self, scan_id)
    except Exception:
        try:
            async with get_db() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(status='failed')
                )
        except Exception:
            logger.exception("Failed to mark scan %s as failed", scan_id)
        raise

async def _execute_zap_scan(self, scan_id):
    self.update_state(state='PROGRESS', meta={'progress': 'Starting scan'})

    # Get scan and application config from DB
    async with get_db() as session:
        scan_result = await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if not scan:
            self.update_state(state='FAILURE', meta={'error': 'Scan not found'})
            return
        
        app_result = await session.execute(
            select(Application).where(Application.id == scan.application_id)
        )
        app = app_result.scalar_one_or_none()
        if not app:
            self.update_state(state='FAILURE', meta={'error': 'Application not found'})
            return
        
        # Update scan status to running
        await session.execute(
            update(Scan).where(Scan.id == scan_id).values(status='running')
        )
    
    # Extract config
    app_config = app.config
    target_url = app_config.get('application', {}).get('base_url', 'http://example.com')
    
    # For now, no auth headers - this would come from auth sessions
    auth_headers = {}
    
    scanner = scanner_registry.create(scan.scanner)
    scan_id_zap = scanner.start_scan(ScanTarget(url=target_url, auth_headers=auth_headers))
    
    self.update_state(state='PROGRESS', meta={'progress': 'Scan in progress'})

    progress = _wait_for_zap_scan(scanner, scan_id_zap, target_url, self)
    self.update_state(
        state='PROGRESS',
        meta={'progress': f'Scan {progress}% complete, collecting findings'},
    )
    
    findings = scanner.get_findings(scan_id_zap)
    
    # Save findings to DB
    async with get_db() as session:
        for finding_data in findings:
            finding = Finding(
                scan_id=scan_id,
                title=finding_data.title,
                description=finding_data.description,
                severity=finding_data.severity,
                url=finding_data.url,
                cwe=finding_data.cwe,
                owasp=finding_data.owasp,
                request=finding_data.request,
                response=finding_data.response,
            )
            session.add(finding)
    
        await session.execute(
            update(Scan).where(Scan.id == scan_id).values(status='completed')
        )
    
    return {'findings': len(findings)}

def _wait_for_zap_scan(scanner, zap_scan_id, target_url, task):
    started_at = time.monotonic()
    consecutive_errors = 0
    last_progress = 0

    while True:
        elapsed = time.monotonic() - started_at
        if elapsed > settings.zap_scan_timeout_seconds:
            raise TimeoutError(
                f"ZAP scan {zap_scan_id} for {target_url} timed out after "
                f"{settings.zap_scan_timeout_seconds} seconds at {last_progress}%"
            )

        try:
            progress = scanner.get_status(zap_scan_id)
            consecutive_errors = 0
            last_progress = progress
        except Exception as exc:
            consecutive_errors += 1
            logger.warning(
                "Failed to poll ZAP scan %s status (%s/%s): %s",
                zap_scan_id,
                consecutive_errors,
                settings.zap_poll_max_errors,
                exc,
            )
            if consecutive_errors >= settings.zap_poll_max_errors:
                raise RuntimeError(
                    f"ZAP scan {zap_scan_id} status polling failed after "
                    f"{consecutive_errors} attempts: {exc}"
                ) from exc

            task.update_state(
                state='PROGRESS',
                meta={
                    'progress': (
                        f'Scan still running, waiting for ZAP status '
                        f'({last_progress}% last seen)'
                    )
                },
            )
            time.sleep(settings.zap_poll_interval_seconds)
            continue

        if progress >= 100:
            return progress

        task.update_state(
            state='PROGRESS',
            meta={'progress': f'Scan {progress}% complete'},
        )
        time.sleep(settings.zap_poll_interval_seconds)

@celery_app.task
def replay_finding(request_data: dict, auth_headers: dict = None):
    async def _replay():
        async with ReplayEngine() as engine:
            return await engine.replay_request(request_data, auth_headers)
    
    return asyncio.run(_replay())

@celery_app.task
def validate_idor(request: dict, identifiers: list, auth_sessions: dict):
    async def _validate():
        async with ReplayEngine() as engine:
            validator = IDORValidator(engine)
            return await validator.validate_idor(request, identifiers, auth_sessions)
    
    return asyncio.run(_validate())
