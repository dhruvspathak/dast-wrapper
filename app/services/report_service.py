from typing import Dict, Any, Optional
import uuid
from datetime import datetime
import json
import os
from app.reporting.report_generator import ReportGenerator

class ReportService:
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = report_dir
        self.generator = ReportGenerator()
        os.makedirs(report_dir, exist_ok=True)

    async def generate_report(self, scan_id: str, scan_data: Dict[str, Any]) -> str:
        report_id = str(uuid.uuid4())
        
        # Generate HTML content
        html_content = self.generator.generate_html_report(scan_data)
        
        # Save to disk
        report_path = os.path.join(self.report_dir, f"{report_id}.html")
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        # Save metadata
        metadata = {
            "report_id": report_id,
            "scan_id": scan_id,
            "generated_at": datetime.utcnow().isoformat(),
            "file_path": report_path
        }
        metadata_path = os.path.join(self.report_dir, f"{report_id}.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        
        return report_id

    async def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        metadata_path = os.path.join(self.report_dir, f"{report_id}.json")
        
        if not os.path.exists(metadata_path):
            return None
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        report_path = metadata.get('file_path')
        if not os.path.exists(report_path):
            return None
        
        with open(report_path, 'r') as f:
            html_content = f.read()
        
        return {
            "report_id": report_id,
            "scan_id": metadata.get('scan_id'),
            "generated_at": metadata.get('generated_at'),
            "content": html_content
        }

    async def get_report_html(self, report_id: str) -> Optional[str]:
        report_path = os.path.join(self.report_dir, f"{report_id}.html")
        
        if not os.path.exists(report_path):
            return None
        
        with open(report_path, 'r') as f:
            return f.read()