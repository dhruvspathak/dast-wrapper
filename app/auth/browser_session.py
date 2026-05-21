from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from playwright.async_api import BrowserContext, async_playwright
import logging

logger = logging.getLogger(__name__)

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
        if state_path and state_path.exists():
            logger.debug("Loading browser storage state from %s", state_path)
            storage_state_arg = str(state_path)
        else:
            storage_state_arg = None
            if state_path:
                logger.debug("No existing storage state at %s; starting fresh context", state_path)

        context = await browser.new_context(storage_state=storage_state_arg)
        try:
            yield context
            if state_path:
                state_path.parent.mkdir(parents=True, exist_ok=True)
                await context.storage_state(path=str(state_path))
                logger.debug("Saved browser storage state to %s", state_path)
        finally:
            await context.close()
            await browser.close()
