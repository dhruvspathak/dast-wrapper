from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.config import settings


class ScannerAdapter(ABC):
    name: str

    @abstractmethod
    async def start_scan(self, target_url: str) -> str:
        raise NotImplementedError

    @abstractmethod
    async def stop_scan(self, scanner_scan_id: str) -> None:
        raise NotImplementedError

    @abstractmethod
    async def inject_context(self, **context: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    async def fetch_findings(self, scanner_scan_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError


class ZAPAdapter(ScannerAdapter):
    name = "zap"

    def __init__(self, api_url: str | None = None):
        self.api_url = (api_url or settings.zap_api_url).rstrip("/")
        self.context_name = "authorization-mvp"

    async def start_scan(self, target_url: str) -> str:
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.get(f"{self.api_url}/JSON/core/action/accessUrl/", params={"url": target_url})
            spider = await client.get(f"{self.api_url}/JSON/spider/action/scan/", params={"url": target_url})
            spider.raise_for_status()
            await client.get(f"{self.api_url}/JSON/ascan/action/scan/", params={"url": target_url})
            active = await client.get(f"{self.api_url}/JSON/ascan/action/scans/")
            active.raise_for_status()
            scans = active.json().get("scans") or []
            return str(scans[-1].get("id") if scans else spider.json().get("scan", "unknown"))

    async def stop_scan(self, scanner_scan_id: str) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.get(f"{self.api_url}/JSON/ascan/action/stop/", params={"scanId": scanner_scan_id})

    async def inject_context(self, **context: Any) -> None:
        application = context.get("application")
        if not application:
            return
        include_regex = f"{application.base_url}.*"
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.get(
                f"{self.api_url}/JSON/context/action/newContext/",
                params={"contextName": self.context_name},
            )
            await client.get(
                f"{self.api_url}/JSON/context/action/includeInContext/",
                params={"contextName": self.context_name, "regex": include_regex},
            )

    async def fetch_findings(self, scanner_scan_id: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{self.api_url}/JSON/core/view/alerts/")
            response.raise_for_status()
            return list(response.json().get("alerts") or [])


def get_scanner_adapter(name: str) -> ScannerAdapter:
    if name == "zap":
        return ZAPAdapter()
    raise ValueError(f"Unsupported scanner backend: {name}")
