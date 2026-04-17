"""Patchright (stealth Playwright) browser setup for Nike.com.br.

Uses `launch_persistent_context` (as recommended by the Patchright docs for
maximum stealth) with a persistent user data dir so cookies, fingerprint,
and device state carry over across runs. This is harder for Akamai / Kasada /
PerimeterX-style bot managers to detect than a fresh launch with extra args.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from patchright.async_api import async_playwright

from nike.config import NikeConfig

logger = logging.getLogger("nike.browser")


@asynccontextmanager
async def browser_context(cfg: NikeConfig):
    """Yield a (browser, context, page) tuple with stealth settings."""
    user_data_dir = os.environ.get(
        "NIKE_USER_DATA_DIR", "/tmp/nike-user-data"
    )
    os.makedirs(user_data_dir, exist_ok=True)
    logger.info("Using persistent user data dir: %s", user_data_dir)

    async with async_playwright() as pw:
        # Per Patchright docs: no custom args, use channel="chrome" if real
        # Chrome is installed (even better stealth). Fall back to bundled
        # Chromium otherwise.
        channel = os.environ.get("NIKE_BROWSER_CHANNEL", "chrome")
        try:
            context = await pw.chromium.launch_persistent_context(
                user_data_dir=user_data_dir,
                channel=channel,
                headless=cfg.headless,
                no_viewport=True,
                locale="pt-BR",
                timezone_id=cfg.timezone,
            )
        except Exception as e:
            logger.warning(
                "Could not launch with channel=%s (%s), falling back to bundled chromium",
                channel, e,
            )
            context = await pw.chromium.launch_persistent_context(
                user_data_dir=user_data_dir,
                headless=cfg.headless,
                no_viewport=True,
                locale="pt-BR",
                timezone_id=cfg.timezone,
            )

        # Persistent context always has at least one page
        page = context.pages[0] if context.pages else await context.new_page()

        try:
            yield None, context, page
        finally:
            await context.close()
