from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List
import yaml

from app.schemas.application import ApplicationConfig
from app.services.scan_service import ScanService

router = APIRouter()
scan_service = ScanService()

@router.post("/upload-config")
async def upload_config(file: UploadFile = File(...)):
    if not file.filename.endswith('.yaml'):
        raise HTTPException(status_code=400, detail="Only YAML files are allowed")
    
    content = await file.read()
    try:
        config_data = yaml.safe_load(content)
        config = ApplicationConfig(**config_data)
        # Save config or process
        return {"message": "Config uploaded successfully", "config": config.dict()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid config: {str(e)}")

@router.post("/start-scan")
async def start_scan(config_id: str):
    # Start scan job
    job_id = await scan_service.start_scan(config_id)
    return {"job_id": job_id}

@router.get("/scan-status/{job_id}")
async def get_scan_status(job_id: str):
    status = await scan_service.get_scan_status(job_id)
    return {"status": status}

@router.get("/findings/{scan_id}")
async def get_findings(scan_id: str):
    findings = await scan_service.get_findings(scan_id)
    return {"findings": findings}