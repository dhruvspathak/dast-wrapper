from app.workers.celery_app import celery_app
from app.scanners.zap_scanner import ZAPScanner
from app.replay.replay_engine import ReplayEngine
from app.validators.idor_validator import IDORValidator
import asyncio

@celery_app.task
def run_zap_scan(target_url: str, auth_headers: dict = None):
    scanner = ZAPScanner()
    scan_id = scanner.start_scan(target_url, auth_headers)
    # Wait for completion (simplified)
    while scanner.get_scan_status(scan_id) < 100:
        import time
        time.sleep(5)
    findings = scanner.get_findings(scan_id)
    return findings

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