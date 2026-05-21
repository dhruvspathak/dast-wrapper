from __future__ import annotations

import time
from typing import Any

from playwright.async_api import async_playwright

from app.models.application import Application
from app.models.authorization import Identity, ScanJob, Session
from app.storage.traffic_store import TrafficStore


class AuthenticatedCrawler:
    def __init__(self, traffic_store: TrafficStore, max_pages: int = 50):
        self.traffic_store = traffic_store
        self.max_pages = max_pages

    async def crawl(
        self,
        application: Application,
        scan_job: ScanJob,
        identity: Identity,
        session: Session,
    ) -> list[str]:
        discovered_urls: set[str] = set()
        state_path = session.storage_state_path
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox"],
            )
            context = await browser.new_context(storage_state=state_path)
            page = await context.new_page()

            started: dict[str, float] = {}

            async def on_request(request) -> None:
                started[request.url] = time.perf_counter()

            async def on_response(response) -> None:
                request = response.request
                if not request.url.startswith(application.base_url):
                    return
                body = None
                try:
                    body = await response.text()
                except Exception:
                    body = None
                request_body = None
                try:
                    request_body = request.post_data
                except Exception:
                    request_body = None
                discovered_urls.add(request.url)
                await self.traffic_store.record(
                    {
                        "workspace_id": scan_job.workspace_id,
                        "application_id": application.id,
                        "scan_job_id": scan_job.id,
                        "identity_id": identity.id,
                        "session_id": session.id,
                        "request_url": request.url,
                        "request_method": request.method,
                        "request_headers": await request.all_headers(),
                        "request_body": request_body,
                        "response_status": response.status,
                        "response_headers": await response.all_headers(),
                        "response_body": body,
                        "response_size": len(body or ""),
                        "elapsed_ms": (time.perf_counter() - started.get(request.url, time.perf_counter())) * 1000,
                        "source": "crawler",
                    }
                )

            page.on("request", on_request)
            page.on("response", on_response)
            await page.goto(application.base_url, wait_until="networkidle")
            await self._walk_links(page, application.base_url, discovered_urls)
            await browser.close()
        return sorted(discovered_urls)

    async def _walk_links(self, page, base_url: str, discovered_urls: set[str]) -> None:
        visited = {page.url}
        queue = [page.url]
        auth_boundary_tokens = {"/login", "/signin", "/sign-in", "/auth", "/account/login", "/oauth"}
        static_tokens = {"/_next/", ".js", ".css", ".map", ".ico", "static/", ".png", ".jpg", ".jpeg", ".svg"}
        while queue and len(visited) < self.max_pages:
            current = queue.pop(0)
            try:
                await page.goto(current, wait_until="networkidle")
                cur_lower = page.url.lower()
                if any(token in cur_lower for token in auth_boundary_tokens):
                    # hit auth boundary; do not traverse further from this page
                    continue
                if any(token in cur_lower for token in static_tokens):
                    # skip static/asset pages
                    continue
                hrefs: list[Any] = await page.eval_on_selector_all(
                    "a[href]",
                    "links => links.map(link => link.href)",
                )
            except Exception:
                continue
            for href in hrefs:
                if (
                    isinstance(href, str)
                    and href.startswith(base_url)
                    and href not in visited
                    and not any(token in href.lower() for token in auth_boundary_tokens)
                    and not any(token in href.lower() for token in static_tokens)
                ):
                    visited.add(href)
                    discovered_urls.add(href)
                    queue.append(href)
