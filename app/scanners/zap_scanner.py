import zapv2
from typing import Dict, List, Any
import time
import logging
from requests.exceptions import RequestException

from app.core.config import settings
from app.scanners.base import ScannerFinding, ScannerPlugin, ScanTarget

logger = logging.getLogger(__name__)

class ZAPScanner(ScannerPlugin):
    name = "zap"

    def __init__(self, api_url: str | None = None):
        self.api_url = api_url or settings.zap_api_url
        self.zap = zapv2.ZAPv2(
            apikey="",
            proxies={'http': self.api_url, 'https': self.api_url},
            validate_status_code=True,
        )

    def wait_until_ready(self, timeout_seconds: int = 60) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_error = None

        while time.monotonic() < deadline:
            try:
                _ = self.zap.core.version
                return
            except Exception as exc:
                last_error = exc
                time.sleep(2)

        raise RuntimeError(
            f"ZAP API is not ready at {self.api_url}: {last_error}"
        )

    def start_scan(self, target: ScanTarget | str, auth_headers: Dict[str, str] = None) -> str:
        if isinstance(target, ScanTarget):
            target_url = target.url
            auth_headers = target.auth_headers
        else:
            target_url = target

        self.wait_until_ready()

        # Set target
        try:
            self.zap.urlopen(target_url)
        except RequestException as exc:
            raise RuntimeError(
                f"ZAP proxy at {self.api_url} could not open target {target_url}: {exc}"
            ) from exc

        # Import context if needed
        # self.zap.context.import_context(...)

        # Set auth headers
        if auth_headers:
            for header, value in auth_headers.items():
                self.zap.httpsessions.add_http_session_token(target_url, header, value)

        # Start spider
        try:
            spider_id = self.zap.spider.scan(target_url)
        except Exception as exc:
            raise RuntimeError(
                f"ZAP spider failed for {target_url} via {self.api_url}: {exc}"
            ) from exc
        logger.info(f"Started spider scan: {spider_id}")

        # Wait for spider to complete
        while int(self.zap.spider.status(spider_id)) < 100:
            time.sleep(1)

        # Start active scan
        scan_id = self.zap.ascan.scan(target_url)
        logger.info(f"Started active scan: {scan_id}")

        return scan_id

    def get_status(self, scan_id: str) -> int:
        return int(self.zap.ascan.status(scan_id))

    def get_scan_status(self, scan_id: str) -> int:
        return self.get_status(scan_id)

    def get_findings(self, scan_id: str) -> List[ScannerFinding]:
        # Get alerts
        alerts = self.zap.core.alerts()

        findings = []
        for alert in alerts:
            findings.append(
                ScannerFinding(
                    title=alert.get('alert') or '',
                    description=alert.get('description'),
                    severity=alert.get('risk') or 'info',
                    url=alert.get('url'),
                    cwe=alert.get('cweid'),
                    request=alert.get('request'),
                    response=alert.get('response'),
                    raw=alert,
                )
            )

        return findings

    def export_results(self, scan_id: str, format: str = 'json') -> str:
        # Export results
        if format == 'json':
            return self.zap.core.jsonreport()
        elif format == 'html':
            return self.zap.core.htmlreport()
        else:
            return self.zap.core.xmlreport()
