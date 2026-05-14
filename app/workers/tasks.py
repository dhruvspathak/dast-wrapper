from app.workers.celery_app import celery_app
from app.scanners.base import ScanTarget
from app.scanners.registry import scanner_registry
from app.replay.replay_engine import ReplayEngine
from app.validators.idor_validator import IDORValidator
from app.validators.authorization_engine import AuthorizationValidationEngine
from app.auth.context_manager import AuthContextManager
from app.auth.playwright_auth import PlaywrightAuthEngine
from app.ai.triage_engine import AITriageEngine
import asyncio
from app.db.base import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.application import Application
from app.core.config import settings
from sqlalchemy import select, update
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="run_zap_scan")
def run_zap_scan(self, scan_id):
    # Run this in a new event loop since Celery runs in a separate thread
    return asyncio.run(_run_zap_scan_async(self, scan_id))

async def _run_zap_scan_async(self, scan_id):
    try:
        return await _execute_zap_scan(self, scan_id)
    except Exception as exc:
        try:
            status = "cancelled" if "cancellation requested" in str(exc).lower() else "failed"
            async with get_db() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(status=status, completed_at=datetime.utcnow())
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
            update(Scan).where(Scan.id == scan_id).values(status='running', started_at=datetime.utcnow())
        )
    
    # Extract config
    app_config = app.config
    target_url = app_config.get('application', {}).get('base_url', 'http://example.com')
    
    # Perform authentication if configured
    auth_headers = {}
    cookies = {}
    auth_config = app_config.get('authentication')
    if auth_config and auth_config.get('type') == 'playwright_jwt':
        try:
            self.update_state(state='PROGRESS', meta={'progress': 'Performing authentication'})
            login_url = auth_config.get('login_url')
            # Default to admin role for scan if multiple roles exist
            users = auth_config.get('users', {})
            role = 'admin' if 'admin' in users else list(users.keys())[0] if users else None
            user_data = users.get(role) if role else None
            
            if login_url and user_data:
                async with PlaywrightAuthEngine(workspace_id=scan.workspace_id, application_id=scan.application_id, role=role) as auth_engine:
                    auth_context = await auth_engine.authenticate(
                        login_url=login_url,
                        username=user_data.get('username'),
                        password=user_data.get('password')
                    )
                    auth_headers = auth_context.headers
                    cookies = auth_context.cookies
                    logger.info(f"Authenticated as {role}, captured {len(cookies)} cookies")
        except Exception as exc:
            logger.exception("Authentication failed, proceeding unauthenticated: %s", exc)

    scanner = scanner_registry.create(scan.scanner)
    scan_id_zap = scanner.start_scan(ScanTarget(url=target_url, auth_headers=auth_headers, cookies=cookies))
    async with get_db() as session:
        await session.execute(
            update(Scan).where(Scan.id == scan_id).values(scanner_scan_id=scan_id_zap)
        )
    
    self.update_state(state='PROGRESS', meta={'progress': 'Scan in progress'})

    progress = await _wait_for_zap_scan(scanner, scan_id_zap, target_url, self, scan_id)
    self.update_state(
        state='PROGRESS',
        meta={'progress': f'Scan {progress}% complete, collecting findings'},
    )
    
    findings = scanner.get_findings(scan_id_zap)
    
    processed = 0
    validated = 0
    manual_review = 0

    # Save findings to DB after replay/auth/AI validation enriches each item.
    async with get_db() as session:
        auth_contexts = await AuthContextManager(session).list_contexts(
            application_id=scan.application_id,
            workspace_id=scan.workspace_id,
            roles=app_config.get("roles") or None,
        )
        async with ReplayEngine(allowed_hosts=settings.allowed_replay_hosts) as replay_engine:
            auth_validator = AuthorizationValidationEngine(replay_engine)
            triage_engine = AITriageEngine()

            for finding_data in findings:
                canonical = scanner.normalize_finding(
                    scan_id=scan_id,
                    finding=finding_data,
                    workspace_id=scan.workspace_id,
                )
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'progress': (
                            f'Validating finding {processed + 1}/{len(findings)} '
                            'with replay, auth, IDOR/BOLA, and triage'
                        )
                    },
                )
                validation = await _validate_canonical_finding(
                    canonical=canonical,
                    replay_engine=replay_engine,
                    auth_validator=auth_validator,
                    triage_engine=triage_engine,
                    auth_contexts=auth_contexts,
                )
                processed += 1
                if validation["validation_status"] in {"confirmed", "likely"}:
                    validated += 1
                else:
                    manual_review += 1

                finding = Finding(
                    workspace_id=canonical.workspace_id,
                    scan_id=scan_id,
                    scanner=canonical.scanner,
                    scanner_finding_id=canonical.scanner_finding_id,
                    fingerprint=canonical.fingerprint,
                    title=canonical.title,
                    description=canonical.description,
                    severity=canonical.severity,
                    url=canonical.url,
                    cwe=canonical.cwe,
                    owasp=canonical.owasp,
                    request=canonical.request.model_dump(mode="json") if canonical.request else None,
                    response=canonical.response.model_dump(mode="json") if canonical.response else None,
                    evidence=canonical.evidence,
                    raw=canonical.raw,
                    exploitability_score=validation["exploitability_score"],
                    validation_status=validation["validation_status"],
                    ai_analysis=validation["ai_analysis"],
                    replay_results=validation["replay_results"],
                )
                session.add(finding)

        await session.execute(
            update(Scan).where(Scan.id == scan_id).values(
                status='completed',
                completed_at=datetime.utcnow(),
                results={
                    "scanner_findings": len(findings),
                    "validated_findings": validated,
                    "manual_review_findings": manual_review,
                    "auth_contexts": len(auth_contexts),
                },
            )
        )
    
    return {'findings': len(findings), 'validated_findings': validated, 'manual_review_findings': manual_review}


async def _validate_canonical_finding(
    canonical,
    replay_engine: ReplayEngine,
    auth_validator: AuthorizationValidationEngine,
    triage_engine: AITriageEngine,
    auth_contexts: list,
) -> dict:
    replay_results = []
    validation_results = []

    if canonical.request:
        try:
            replay = await replay_engine.replay_canonical(
                canonical.request,
                baseline_response=canonical.response,
            )
            replay_results.append(replay.model_dump(mode="json"))
        except Exception as exc:
            replay_results.append({"success": False, "error": str(exc)})

        if len(auth_contexts) >= 2:
            try:
                authorization = await auth_validator.validate(canonical.request, auth_contexts)
                validation_results.append(authorization.model_dump(mode="json"))
            except Exception as exc:
                validation_results.append(
                    {
                        "validator": "authorization",
                        "status": "failed",
                        "confidence": 0.0,
                        "exploitable": False,
                        "evidence": {"error": str(exc)},
                    }
                )
        else:
            validation_results.append(
                {
                    "validator": "authorization",
                    "status": "needs_manual_review",
                    "confidence": 0.2,
                    "exploitable": False,
                    "evidence": {"reason": "At least two role-isolated auth contexts are required"},
                }
            )
    else:
        validation_results.append(
            {
                "validator": "replay",
                "status": "needs_manual_review",
                "confidence": 0.1,
                "exploitable": False,
                "evidence": {"reason": "Scanner did not provide replayable request evidence"},
            }
        )

    ai_analysis = await triage_engine.triage_finding(
        canonical,
        replay_evidence=replay_results,
        validation_results=validation_results,
    )
    exploitability_score = max(
        [item.get("confidence", 0.0) for item in validation_results if item.get("exploitable")]
        or [ai_analysis.get("confidence", 0.0)]
    )
    validation_status = _finding_validation_status(validation_results, ai_analysis)
    return {
        "replay_results": replay_results,
        "ai_analysis": ai_analysis,
        "exploitability_score": exploitability_score,
        "validation_status": validation_status,
    }


def _finding_validation_status(validation_results: list[dict], ai_analysis: dict) -> str:
    for item in validation_results:
        if item.get("status") == "confirmed":
            return "confirmed"
    for item in validation_results:
        if item.get("status") == "likely":
            return "likely"
    classification = str(ai_analysis.get("classification", "")).lower()
    if classification.startswith("confirmed"):
        return "confirmed"
    if classification.startswith("likely"):
        return "likely"
    if "false positive" in classification:
        return "false_positive"
    if "informational" in classification:
        return "informational"
    return "needs_manual_review"

async def _wait_for_zap_scan(scanner, zap_scan_id, target_url, task, scan_id):
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
            if await _scan_cancelled(scan_id):
                raise RuntimeError("Scan cancellation requested")
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
            await asyncio.sleep(settings.zap_poll_interval_seconds)
            continue

        if progress >= 100:
            return progress

        task.update_state(
            state='PROGRESS',
            meta={'progress': f'Scan {progress}% complete'},
        )
        await asyncio.sleep(settings.zap_poll_interval_seconds)

@celery_app.task
def replay_finding(request_data: dict, auth_headers: dict = None):
    async def _replay():
        async with ReplayEngine(allowed_hosts=settings.allowed_replay_hosts) as engine:
            return await engine.replay_request(request_data, auth_headers)
    
    return asyncio.run(_replay())

@celery_app.task
def validate_idor(request: dict, identifiers: list, auth_sessions: dict):
    async def _validate():
        async with ReplayEngine(allowed_hosts=settings.allowed_replay_hosts) as engine:
            validator = IDORValidator(engine)
            return await validator.validate_idor(request, identifiers, auth_sessions)
    
    return asyncio.run(_validate())


async def _scan_cancelled(scan_id: str | None) -> bool:
    if not scan_id:
        return False
    async with get_db() as session:
        result = await session.execute(select(Scan.status).where(Scan.id == scan_id))
        return result.scalar_one_or_none() in {"cancelling", "cancelled"}
