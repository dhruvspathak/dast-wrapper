from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List
import yaml
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.schemas.application import ApplicationConfig
from app.services.scan_service import ScanService
from app.db.base import get_db
from app.models.application import Application

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
            await session.commit()
            await session.refresh(app)
        
        return {"message": "Config uploaded successfully", "config_id": app.id}
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

@router.get("/findings/{scan_id}")
async def get_findings(scan_id: str):
    findings = await scan_service.get_findings(scan_id)
    return {"findings": findings}
