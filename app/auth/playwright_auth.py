from pathlib import Path
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from typing import Dict, Any, Optional

from app.auth.context_manager import session_state_path
from app.schemas.canonical import AuthContext

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
        application_id: str | None = None,
        role: str | None = None,
    ) -> AuthContext:
        if not self.page:
            raise RuntimeError("Auth engine not initialized")

        await self.page.goto(login_url)

        # Assume standard login form
        await self.page.fill('input[name="username"]', username)
        await self.page.fill('input[name="password"]', password)
        await self.page.click('button[type="submit"]')

        # Wait for navigation or success
        await self.page.wait_for_load_state('networkidle')

        # Extract tokens
        auth_data: dict[str, Any] = {}

        # JWT from localStorage
        jwt = await self.page.evaluate("() => localStorage.getItem('jwt')")
        if jwt:
            auth_data['jwt'] = jwt

        # Cookies
        cookies = await self.page.context.cookies()
        auth_data['cookies'] = {c['name']: c['value'] for c in cookies}

        # Headers for future requests
        auth_data['headers'] = {}
        if jwt:
            auth_data['headers']['Authorization'] = f"Bearer {jwt}"

        local_storage = await self.page.evaluate("() => Object.assign({}, localStorage)")
        session_storage = await self.page.evaluate("() => Object.assign({}, sessionStorage)")
        app_id = application_id or self.application_id
        role_name = role or self.role
        if not app_id or not role_name:
            raise RuntimeError("application_id and role are required to build an AuthContext")

        return AuthContext(
            application_id=app_id,
            workspace_id=self.workspace_id,
            role=role_name,
            headers=auth_data["headers"],
            cookies=auth_data["cookies"],
            local_storage=local_storage,
            session_storage=session_storage,
            refresh_token=local_storage.get("refresh_token") or local_storage.get("refreshToken"),
            browser_storage_state_path=session_state_path(self.workspace_id, app_id, role_name),
        )

    async def get_session_data(self) -> Dict[str, Any]:
        if not self.page:
            raise RuntimeError("No active session")

        # Extract current session data
        local_storage = await self.page.evaluate("() => Object.assign({}, localStorage)")
        session_storage = await self.page.evaluate("() => Object.assign({}, sessionStorage)")
        cookies = await self.page.context.cookies()

        return {
            'localStorage': local_storage,
            'sessionStorage': session_storage,
            'cookies': cookies
        }
