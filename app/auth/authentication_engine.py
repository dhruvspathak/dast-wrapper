from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from playwright.async_api import Page, async_playwright

from app.auth.identity_engine import IdentityEngine
from app.models.application import Application
from app.models.authorization import Identity, Session
from app.utils.security import decrypt_data


SESSION_STATE_ROOT = Path("reports/browser-state")


class AuthenticationIntelligenceEngine:
    def __init__(self, identity_engine: IdentityEngine):
        self.identity_engine = identity_engine

    async def authenticate(self, application: Application, identity: Identity) -> Session:
        password = ""
        if identity.encrypted_credentials.get("password"):
            password = decrypt_data(identity.encrypted_credentials["password"])

        state_path = self._state_path(identity)
        traffic: list[dict[str, Any]] = []
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox"],
            )
            context = await browser.new_context(
                storage_state=str(state_path) if state_path.exists() else None
            )
            page = await context.new_page()
            self._capture_auth_traffic(page, traffic)

            login_url = identity.login_config.get("login_url") or application.base_url
            await page.goto(login_url, wait_until="domcontentloaded")
            await self._submit_login_form(page, identity, password)
            await page.wait_for_load_state("networkidle")

            local_storage = await page.evaluate("() => Object.assign({}, localStorage)")
            session_storage = await page.evaluate("() => Object.assign({}, sessionStorage)")
            cookies = await context.cookies()
            cookie_map = {cookie["name"]: cookie["value"] for cookie in cookies}
            tokens = self._extract_tokens(local_storage, session_storage, cookie_map)
            headers = dict(identity.auth_headers or {})
            if tokens.get("jwt") and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {tokens['jwt']}"

            state_path.parent.mkdir(parents=True, exist_ok=True)
            await context.storage_state(path=str(state_path))
            await browser.close()

        return await self.identity_engine.upsert_session(
            identity,
            cookies=cookie_map,
            local_storage=local_storage,
            session_storage=session_storage,
            auth_headers=headers,
            tokens=tokens,
            storage_state_path=str(state_path),
            traffic_history=traffic,
        )

    async def refresh_session(self, application: Application, identity: Identity) -> Session:
        return await self.authenticate(application, identity)

    async def _submit_login_form(self, page: Page, identity: Identity, password: str) -> None:
        config = identity.login_config or {}
        username_selector = config.get("username_selector") or await self._detect_username_field(page)
        password_selector = config.get("password_selector") or await self._detect_password_field(page)
        submit_selector = config.get("submit_selector") or "button[type=submit], input[type=submit]"

        if identity.username and username_selector:
            await page.locator(username_selector).first.fill(identity.username)
        if password and password_selector:
            await page.locator(password_selector).first.fill(password)

        for step in config.get("extra_steps") or []:
            if step.get("type") == "click" and step.get("selector"):
                await page.locator(step["selector"]).first.click()
            if step.get("type") == "fill" and step.get("selector"):
                await page.locator(step["selector"]).first.fill(str(step.get("value", "")))

        await page.locator(submit_selector).first.click()

    async def _detect_username_field(self, page: Page) -> str | None:
        candidates = [
            "input[type=email]",
            "input[name*=email i]",
            "input[name*=user i]",
            "input[id*=email i]",
            "input[id*=user i]",
            "input[type=text]",
        ]
        return await self._first_existing_selector(page, candidates)

    async def _detect_password_field(self, page: Page) -> str | None:
        return await self._first_existing_selector(page, ["input[type=password]", "input[name*=pass i]"])

    async def _first_existing_selector(self, page: Page, selectors: list[str]) -> str | None:
        for selector in selectors:
            if await page.locator(selector).count() > 0:
                return selector
        return None

    def _extract_tokens(
        self,
        local_storage: dict[str, Any],
        session_storage: dict[str, Any],
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        token_sources = {**cookies, **local_storage, **session_storage}
        tokens: dict[str, Any] = {}
        jwt_pattern = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
        for key, value in token_sources.items():
            if not isinstance(value, str):
                continue
            lowered = key.lower()
            if jwt_pattern.match(value):
                tokens.setdefault("jwt", value)
                tokens[key] = value
            elif "token" in lowered or "session" in lowered:
                tokens[key] = value
        return tokens

    def _capture_auth_traffic(self, page: Page, traffic: list[dict[str, Any]]) -> None:
        async def on_response(response) -> None:
            request = response.request
            traffic.append(
                {
                    "url": request.url,
                    "method": request.method,
                    "request_headers": await request.all_headers(),
                    "response_status": response.status,
                    "response_headers": await response.all_headers(),
                }
            )

        page.on("response", on_response)

    def _state_path(self, identity: Identity) -> Path:
        return SESSION_STATE_ROOT / identity.workspace_id / identity.application_id / f"{identity.id}.json"
