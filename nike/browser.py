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

    Modes (checked in order):

    1. CDP mode (NIKE_CDP_URL set): connect to an existing Chrome the user
       launched manually. Launch Chrome first:
         Chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome
       Then set NIKE_CDP_URL=http://localhost:9222.

    2. Storage-state mode (NIKE_STORAGE_STATE_JSON or NIKE_STORAGE_STATE
       file exists): launch chromium NON-persistently and inject cookies +
       localStorage. Used for headless runs on Railway where there's no
       browser UI available for manual login.

    3. Launch mode (default): Patchright launch_persistent_context with
       real Chrome (channel="chrome") → bundled Chromium fallback.
    """
    import json
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

        storage_json = os.environ.get("NIKE_STORAGE_STATE_JSON", "").strip()
        storage_path = os.environ.get("NIKE_STORAGE_STATE", "").strip()
        if storage_json or (storage_path and os.path.exists(storage_path)):
            if storage_json:
                storage = json.loads(storage_json)
                logger.info(
                    "Using NIKE_STORAGE_STATE_JSON (%d cookies)",
                    len(storage.get("cookies", [])),
                )
            else:
                with open(storage_path) as f:
                    storage = json.load(f)
                logger.info("Using storage state from %s", storage_path)
            browser = await pw.chromium.launch(
                channel=os.environ.get("NIKE_BROWSER_CHANNEL", "chrome"),
                headless=cfg.headless,
                args=["--no-sandbox", "--disable-dev-shm-usage"] if cfg.headless else [],
            ) if False else None
            # Patchright's stealth is weaker with non-persistent launches,
            # so prefer launch_persistent_context even here — we just
            # preload cookies via add_cookies after launch.
            user_data_dir = os.environ.get("NIKE_USER_DATA_DIR", "/tmp/nike-user-data")
            os.makedirs(user_data_dir, exist_ok=True)
            context = await pw.chromium.launch_persistent_context(
                user_data_dir=user_data_dir,
                channel=os.environ.get("NIKE_BROWSER_CHANNEL", "chrome"),
                headless=cfg.headless,
                no_viewport=True,
                locale="pt-BR",
                timezone_id=cfg.timezone,
            )
            if storage.get("cookies"):
                await context.add_cookies(storage["cookies"])
                logger.info("Injected %d cookies", len(storage["cookies"]))
            page = context.pages[0] if context.pages else await context.new_page()
            try:
                yield None, context, page
            finally:
                await context.close()
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
