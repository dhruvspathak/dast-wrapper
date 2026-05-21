import asyncio
import logging
import re
from pathlib import Path
from typing import Dict, Any, Optional

from playwright.async_api import async_playwright, Browser, BrowserContext, Page

from app.auth.assertions import AuthAssertionEngine
from app.auth.context_manager import session_state_path
from app.schemas.canonical import AuthContext

logger = logging.getLogger(__name__)

DEFAULT_USERNAME_SELECTORS = [
    'input[name="username"]',
    'input[name="email"]',
    'input[type="email"]',
    'input[name*="user"]',
    'input[id*="user"]',
]
DEFAULT_PASSWORD_SELECTORS = [
    'input[name="password"]',
    'input[type="password"]',
    'input[id*="password"]',
    'input[name*="pass"]',
]
DEFAULT_SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Log in")',
    'button:has-text("Sign in")',
]


class PlaywrightAuthEngine:
    def __init__(self, workspace_id: str = "default", application_id: str | None = None, role: str | None = None):
        self.workspace_id = workspace_id
        self.application_id = application_id
        self.role = role
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-extensions",
            ],
        )
        storage_path = None
        if self.application_id and self.role:
            storage_path = Path(session_state_path(self.workspace_id, self.application_id, self.role))
            storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.context = await self.browser.new_context(
            storage_state=str(storage_path) if storage_path and storage_path.exists() else None
        )
        self.page = await self.context.new_page()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.page:
            await self.page.close()
        if self.context:
            if self.application_id and self.role:
                await self.context.storage_state(
                    path=session_state_path(self.workspace_id, self.application_id, self.role)
                )
            await self.context.close()
        if self.browser:
            await self.browser.close()
        await self.playwright.stop()

    async def authenticate(
        self,
        login_url: str,
        username: str,
        password: str,
        application_url: str | None = None,
        application_id: str | None = None,
        role: str | None = None,
    ) -> AuthContext:
        if not self.page:
            raise RuntimeError("Auth engine not initialized")

        logger.info("Starting browser authentication flow for %s", login_url)
        await self.page.goto(login_url, wait_until="domcontentloaded")
        await self.page.wait_for_load_state("networkidle")

        username_selector = await self._detect_selector(DEFAULT_USERNAME_SELECTORS)
        password_selector = await self._detect_selector(DEFAULT_PASSWORD_SELECTORS)
        submit_selector = await self._detect_selector(DEFAULT_SUBMIT_SELECTORS)

        if username_selector and username:
            await self.page.fill(username_selector, username)
        if password_selector and password:
            await self.page.fill(password_selector, password)
        if submit_selector:
            await self.page.click(submit_selector)
        else:
            raise RuntimeError("Unable to locate login submit button")

        await self._wait_for_auth_flow(login_url)
        await self._wait_for_hydration()

        local_storage = await self.page.evaluate("() => Object.assign({}, localStorage)")
        session_storage = await self.page.evaluate("() => Object.assign({}, sessionStorage)")
        cookies = await self.page.context.cookies()
        cookie_map = {cookie["name"]: cookie["value"] for cookie in cookies}

        jwt = await self._extract_jwt(local_storage, session_storage, cookie_map)
        auth_headers: dict[str, str] = {}
        if jwt:
            auth_headers["Authorization"] = f"Bearer {jwt}"

        app_id = application_id or self.application_id
        role_name = role or self.role
        if not app_id or not role_name:
            raise RuntimeError("application_id and role are required to build an AuthContext")

        auth_context = AuthContext(
            application_id=app_id,
            workspace_id=self.workspace_id,
            role=role_name,
            headers=auth_headers,
            cookies=cookie_map,
            local_storage=local_storage,
            session_storage=session_storage,
            refresh_token=local_storage.get("refresh_token") or local_storage.get("refreshToken"),
            browser_storage_state_path=session_state_path(self.workspace_id, app_id, role_name),
        )

        if application_url:
            assertion_report = await AuthAssertionEngine().validate(
                self.page,
                auth_context,
                application_base_url=application_url,
                login_url=login_url,
            )
            auth_context.metadata["auth_assertions"] = assertion_report.as_dict()
            auth_context.metadata["authenticated_routes"] = assertion_report.discovered_routes
            if assertion_report.confidence_level == "low":
                raise RuntimeError(
                    "Authentication completed but failed auth confidence validation: "
                    f"{assertion_report.confidence_level}"
                )

        return auth_context

    async def _detect_selector(self, selectors: list[str]) -> str | None:
        for selector in selectors:
            try:
                if await self.page.locator(selector).count() > 0:
                    return selector
            except Exception:
                continue
        return None

    async def _wait_for_auth_flow(self, login_url: str) -> None:
        try:
            navigation_task = asyncio.create_task(
                self.page.wait_for_navigation(wait_until="networkidle", timeout=30000)
            )
            response_task = asyncio.create_task(
                self.page.wait_for_response(
                    lambda response: response.url != login_url and response.status < 500,
                    timeout=30000,
                )
            )
            done, pending = await asyncio.wait(
                {navigation_task, response_task},
                timeout=30000,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
        except Exception as exc:
            logger.debug("Auth flow wait completed with exception: %s", exc)
        await self.page.wait_for_load_state("networkidle", timeout=30000)

    async def _wait_for_hydration(self) -> None:
        try:
            await self.page.wait_for_timeout(2000)
        except Exception:
            pass

    async def _extract_jwt(
        self,
        local_storage: dict[str, Any],
        session_storage: dict[str, Any],
        cookies: dict[str, str],
    ) -> str | None:
        jwt_pattern = r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
        for source in [local_storage, session_storage, cookies]:
            for value in source.values():
                if isinstance(value, str) and re.match(jwt_pattern, value):
                    return value
        return None

    async def get_session_data(self) -> Dict[str, Any]:
        if not self.page:
            raise RuntimeError("No active session")

        local_storage = await self.page.evaluate("() => Object.assign({}, localStorage)")
        session_storage = await self.page.evaluate("() => Object.assign({}, sessionStorage)")
        cookies = await self.page.context.cookies()

        return {
            'localStorage': local_storage,
            'sessionStorage': session_storage,
            'cookies': cookies,
        }
