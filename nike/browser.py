"""Patchright (stealth Playwright) browser setup for Nike.com.br."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from patchright.async_api import async_playwright

from nike.config import NikeConfig

logger = logging.getLogger("nike.browser")


@asynccontextmanager
async def browser_context(cfg: NikeConfig):
    """Yield a (browser, context, page) tuple with stealth settings.

    Reuses a persisted storage_state if present so we don't have to log in
    on every run.
    """
    async with async_playwright() as pw:
        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--no-sandbox",
        ]
        browser = await pw.chromium.launch(
            headless=cfg.headless,
            args=launch_args,
        )

        storage_state = (
            cfg.storage_state_path
            if cfg.storage_state_path and os.path.exists(cfg.storage_state_path)
            else None
        )
        if storage_state:
            logger.info("Loading stored session: %s", storage_state)

        context = await browser.new_context(
            user_agent=cfg.user_agent,
            locale="pt-BR",
            timezone_id=cfg.timezone,
            viewport={"width": 1366, "height": 768},
            storage_state=storage_state,
        )

        page = await context.new_page()
        try:
            yield browser, context, page
        finally:
            try:
                if cfg.storage_state_path:
                    await context.storage_state(path=cfg.storage_state_path)
                    logger.info("Saved session to %s", cfg.storage_state_path)
            except Exception as e:
                logger.warning("Could not save storage state: %s", e)
            await context.close()
            await browser.close()
