from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from app.services.report_service import ReportService
from app.services.scan_service import ScanService
from app.db.base import get_db
from app.models.application import Application
from app.models.scan import Scan
from sqlalchemy import select

router = APIRouter()
report_service = ReportService()
scan_service = ScanService()

@router.post("/generate-report/{scan_id}")
async def generate_report(scan_id: str):
    """Generate HTML report for a scan"""
    # Fetch real scan data
    async with get_db() as session:
        scan_result = await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        app_result = await session.execute(
            select(Application).where(Application.id == scan.application_id)
        )
        app = app_result.scalar_one_or_none()
        
        findings = await scan_service.get_findings(scan_id)
    
    scan_data = {
        "application_name": app.name if app else "Unknown",
        "scan_date": scan.created_at.isoformat() if scan else "Unknown",
        "findings": findings
    }
    
    report_id = await report_service.generate_report(scan_id, scan_data)
    return {"message": "Report generated successfully", "scan_id": scan_id, "report_id": report_id}

@router.get("/report/{report_id}")
async def get_report(report_id: str):
    """Get report data as JSON"""
    report = await report_service.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@router.get("/report/{report_id}/download")
async def download_report(report_id: str):
    """Download report as HTML file"""
    html_content = await report_service.get_report_html(report_id)
    if not html_content:
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(content=html_content)