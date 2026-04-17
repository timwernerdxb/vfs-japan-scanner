"""Nike.com.br login flow.

Nike Brasil uses the global Nike accounts system. The login page is typically
reached from the header icon on nike.com.br and redirects through
accounts.nike.com or unite.nike.com.

This module is deliberately resilient: Nike rotates selectors and flow
fragments frequently, so we try several known selectors and log aggressively
to make post-mortem debugging easy.
"""

from __future__ import annotations

import asyncio
import logging

from patchright.async_api import BrowserContext, Page, TimeoutError as PlaywrightTimeout

from nike.config import NikeConfig

logger = logging.getLogger("nike.login")

LOGIN_URL = "https://www.nike.com.br/login"

EMAIL_SELECTORS = [
    'input[name="emailAddress"]',
    'input[type="email"]',
    'input[autocomplete="username"]',
    'input[data-testid="email-input"]',
]

PASSWORD_SELECTORS = [
    'input[name="password"]',
    'input[type="password"]',
    'input[autocomplete="current-password"]',
    'input[data-testid="password-input"]',
]

SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'button:has-text("ENTRAR")',
    'button:has-text("Entrar")',
    'button:has-text("SIGN IN")',
    'button[data-testid="submit-button"]',
]


async def _fill_first_match(page: Page, selectors: list[str], value: str) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            await el.wait_for(state="visible", timeout=3000)
            await el.fill(value)
            logger.info("Filled %r via selector %s", sel, sel)
            return True
        except PlaywrightTimeout:
            continue
        except Exception as e:
            logger.debug("Selector %s failed: %s", sel, e)
    return False


async def _click_first_match(page: Page, selectors: list[str]) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            await el.wait_for(state="visible", timeout=3000)
            await el.click()
            logger.info("Clicked %s", sel)
            return True
        except PlaywrightTimeout:
            continue
        except Exception as e:
            logger.debug("Click %s failed: %s", sel, e)
    return False


async def is_logged_in(context: BrowserContext) -> bool:
    """Best-effort check: look for Nike auth cookies."""
    cookies = await context.cookies()
    names = {c["name"] for c in cookies}
    # Nike uses a family of auth cookies; presence of any is a reasonable signal
    return any(n in names for n in ("nike_locale", "anonymousId")) and any(
        n.lower().startswith(("idtoken", "access", "auth", "sso")) for n in names
    )


async def login(context: BrowserContext, page: Page, cfg: NikeConfig) -> bool:
    """Log in to nike.com.br. Returns True on success."""
    if await is_logged_in(context):
        logger.info("Already logged in (cookies present)")
        return True

    logger.info("Navigating to login page: %s", LOGIN_URL)
    await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
    await asyncio.sleep(2)

    if not await _fill_first_match(page, EMAIL_SELECTORS, cfg.email):
        logger.error("Could not find email field")
        await _debug_dump(page, "login-no-email")
        return False

    # Some flows have email-first then password
    await _click_first_match(page, SUBMIT_SELECTORS)
    await asyncio.sleep(2)

    if not await _fill_first_match(page, PASSWORD_SELECTORS, cfg.password):
        logger.error("Could not find password field")
        await _debug_dump(page, "login-no-password")
        return False

    await _click_first_match(page, SUBMIT_SELECTORS)

    # Wait for redirect away from login
    try:
        await page.wait_for_url(
            lambda url: "login" not in url.lower(),
            timeout=30000,
        )
    except PlaywrightTimeout:
        logger.warning("Did not redirect away from login within 30s")

    await asyncio.sleep(3)

    if await is_logged_in(context):
        logger.info("Login successful")
        return True

    logger.error("Login did not produce auth cookies")
    await _debug_dump(page, "login-failed")
    return False


async def _debug_dump(page: Page, tag: str) -> None:
    import os
    debug_dir = os.environ.get("NIKE_DEBUG_DIR", "/tmp")
    try:
        await page.screenshot(path=f"{debug_dir}/nike-{tag}.png", full_page=True)
        html = await page.content()
        with open(f"{debug_dir}/nike-{tag}.html", "w") as f:
            f.write(html)
        logger.info("Debug artifacts saved: %s/nike-%s.{png,html}", debug_dir, tag)
    except Exception as e:
        logger.warning("Debug dump failed: %s", e)
