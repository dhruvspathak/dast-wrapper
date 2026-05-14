from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from playwright.async_api import BrowserContext, async_playwright

@asynccontextmanager
async def browser_context(storage_state_path: str | None = None) -> AsyncIterator[BrowserContext]:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-extensions",
            ],
        )
        state_path = Path(storage_state_path) if storage_state_path else None
        context = await browser.new_context(
            storage_state=str(state_path) if state_path and state_path.exists() else None
        )
        try:
            yield context
            if state_path:
                state_path.parent.mkdir(parents=True, exist_ok=True)
                await context.storage_state(path=str(state_path))
        finally:
            await context.close()
            await browser.close()
