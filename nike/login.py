"""Nike.com.br login — cookies-only strategy.

We don't try to drive Nike's finicky login modal anymore. Instead:

1. Check if the CDP/persistent Chrome profile already has Nike auth cookies.
2. If yes, proceed.
3. If no, wait up to NIKE_MANUAL_LOGIN_TIMEOUT seconds for the user to log
   in manually in the open Chrome window, polling cookies every 3s.

This trades one minute of initial setup for removing the whole brittle
email/password/OTP selector maintenance treadmill.
"""

from __future__ import annotations

import asyncio
import logging
import os

from patchright.async_api import BrowserContext, Page

from nike.config import NikeConfig

logger = logging.getLogger("nike.login")


AUTH_COOKIE_HINTS = ("idtoken", "accesstoken", "access_token", "sso", "auth", "id_token")


async def is_logged_in(context: BrowserContext) -> bool:
    cookies = await context.cookies()
    for c in cookies:
        name = c["name"].lower()
        if any(h in name for h in AUTH_COOKIE_HINTS):
            return True
    return False


async def login(context: BrowserContext, page: Page, cfg: NikeConfig) -> bool:
    """Ensure we're logged in. Returns True once auth cookies are present."""
    if await is_logged_in(context):
        logger.info("Already logged in (auth cookies present)")
        return True

    timeout = int(os.environ.get("NIKE_MANUAL_LOGIN_TIMEOUT", "180"))
    logger.warning(
        "Not logged in. Log in manually in the open Chrome window at "
        "https://www.nike.com.br — I'll wait up to %ds and pick up when "
        "the auth cookies appear.",
        timeout,
    )

    # Navigate the page to Nike so the user has somewhere to click Entrar
    try:
        await page.goto("https://www.nike.com.br/", wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        logger.warning("Could not preload nike.com.br (%s) — continuing anyway", e)

    elapsed = 0
    interval = 3
    while elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval
        if await is_logged_in(context):
            logger.info("Detected auth cookies after %ds — continuing", elapsed)
            return True
        if elapsed % 15 == 0:
            logger.info("Still waiting for login... (%ds / %ds)", elapsed, timeout)

    logger.error("Timed out waiting for manual login")
    return False
