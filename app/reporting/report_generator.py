from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Dict, Any
import os

class ReportGenerator:
    def __init__(self, template_dir: str = "app/templates"):
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_html_report(self, scan_data: Dict[str, Any]) -> str:
        template = self.env.get_template("report.html")
        return template.render(scan_data)

# Sample template content would go in templates/report.html
# For now, placeholder
