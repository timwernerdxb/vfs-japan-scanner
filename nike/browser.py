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
    """Yield a (browser, context, page) tuple.

    Two modes:

    1. CDP mode (NIKE_CDP_URL set): connect to an existing Chrome instance
       the user launched manually. This bypasses most bot-detection because
       the browser wasn't spawned by Playwright. Launch Chrome like this
       first:

         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
             --remote-debugging-port=9222 \\
             --user-data-dir=/tmp/chrome-nike-profile

       Then set NIKE_CDP_URL=http://localhost:9222.

    2. Launch mode (default): Patchright launches Chrome with
       launch_persistent_context (no custom args, channel="chrome" if real
       Chrome is installed). Falls back to bundled Chromium otherwise.
    """
    cdp_url = os.environ.get("NIKE_CDP_URL", "").strip()

    async with async_playwright() as pw:
        if cdp_url:
            logger.info("Connecting to existing Chrome via CDP: %s", cdp_url)
            browser = await pw.chromium.connect_over_cdp(cdp_url)
            # Reuse the first (user-facing) context / page so we inherit any
            # cookies and the browser-launched process signature.
            if browser.contexts:
                context = browser.contexts[0]
            else:
                context = await browser.new_context(
                    locale="pt-BR", timezone_id=cfg.timezone
                )
            page = context.pages[0] if context.pages else await context.new_page()
            try:
                yield browser, context, page
            finally:
                # Don't close the user's browser; just disconnect.
                await browser.close()
            return

        user_data_dir = os.environ.get(
            "NIKE_USER_DATA_DIR", "/tmp/nike-user-data"
        )
        os.makedirs(user_data_dir, exist_ok=True)
        logger.info("Using persistent user data dir: %s", user_data_dir)

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

        page = context.pages[0] if context.pages else await context.new_page()
        try:
            yield None, context, page
        finally:
            await context.close()
