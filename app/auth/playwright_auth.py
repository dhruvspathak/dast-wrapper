from playwright.async_api import async_playwright, Browser, Page
from typing import Dict, Any, Optional
import asyncio
import json

class PlaywrightAuthEngine:
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.page = await self.browser.new_page()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.page:
            await self.page.close()
        if self.browser:
            await self.browser.close()
        await self.playwright.stop()

    async def authenticate(self, login_url: str, username: str, password: str) -> Dict[str, Any]:
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
        auth_data = {}

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

        return auth_data

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