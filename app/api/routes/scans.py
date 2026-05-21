from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List
import yaml
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.schemas.application import ApplicationConfig
from app.schemas.platform import IdentityCreate
from app.services.scan_service import ScanService
from app.db.base import get_db
from app.models.application import Application
from app.auth.identity_engine import IdentityEngine

router = APIRouter()
scan_service = ScanService()

class StartScanRequest(BaseModel):
    config_id: str
    workspace_id: str = "default"

@router.post("/upload-config")
async def upload_config(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="Only YAML config files are allowed")
    
    content = await file.read()
    try:
        config_data = yaml.safe_load(content)
        if not isinstance(config_data, dict):
            raise ValueError("YAML document must contain an application configuration object")
        config = ApplicationConfig(**config_data)
        
        # Save to database
        async with get_db() as session:
            app = Application(
                name=config.application.name,
                base_url=config.application.base_url,
                config=config_data
            )
            session.add(app)
            await session.flush()
            await session.refresh(app)
            identity_ids: list[str] = []
            identity_engine = IdentityEngine(session)
            for identity_data in config.identities:
                identity = await identity_engine.add_identity(
                    application_id=app.id,
                    payload=IdentityCreate(**identity_data),
                    workspace_id=app.workspace_id,
                )
                identity_ids.append(identity.id)
            await session.commit()
        
        return {
            "message": "Config uploaded successfully",
            "config_id": app.id,
            "application_id": app.id,
            "identity_ids": identity_ids,
            "authorization_scan": {
                "endpoint": "/api/v1/authorization/scans",
                "body": {
                    "application_id": app.id,
                    "identity_ids": identity_ids,
                    "scanner_backend": config.scan.get("scanner_backend", "zap"),
                    "config": config.scan,
                },
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid config: {str(e)}")

@router.post("/start-scan")
async def start_scan(request: StartScanRequest):
    # Start scan job
    try:
        return await scan_service.start_scan(request.config_id, request.workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

@router.post("/cancel/{scan_id}")
async def cancel_scan(scan_id: str, workspace_id: str = "default"):
    return await scan_service.cancel_scan(scan_id, workspace_id)

@router.get("/scan-status/{job_id}")
async def get_scan_status(job_id: str):
    status = await scan_service.get_scan_status(job_id)
    return {"status": status}

@router.get("/status-by-scan/{scan_id}")
async def get_status_by_scan(scan_id: str):
    status = await scan_service.get_status_by_scan_id(scan_id)
    return {"status": status}

@router.get("/findings/{scan_id}")
async def get_findings(scan_id: str):
    findings = await scan_service.get_findings(scan_id)
    return {"findings": findings}
