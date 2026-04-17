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

HOME_URL = "https://www.nike.com.br/"

COOKIE_ACCEPT_SELECTORS = [
    'button:has-text("Aceitar")',
    'button:has-text("ACEITAR")',
    'button#onetrust-accept-btn-handler',
    'button[data-testid="cookie-accept"]',
]

ENTRAR_LINK_SELECTORS = [
    'a:has-text("Entrar")',
    'a:has-text("ENTRAR")',
    'button:has-text("Entrar")',
    'a[href*="login"]',
    'a[href*="signin"]',
]

EMAIL_SELECTORS = [
    'input[name="emailAddress"]',
    'input[name="email"]',
    'input[type="email"]',
    'input[autocomplete="username"]',
    'input[data-testid="email-input"]',
    'input[id*="email" i]',
]

PASSWORD_SELECTORS = [
    'input[name="password"]',
    'input[type="password"]',
    'input[autocomplete="current-password"]',
    'input[data-testid="password-input"]',
    'input[id*="password" i]',
]

SUBMIT_SELECTORS = [
    'button[type="submit"]:not([disabled])',
    'button:has-text("ENTRAR"):not([disabled])',
    'button:has-text("Entrar"):not([disabled])',
    'button:has-text("SIGN IN"):not([disabled])',
    'button:has-text("Continuar"):not([disabled])',
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


async def _dismiss_cookie_banner(page: Page) -> None:
    for sel in COOKIE_ACCEPT_SELECTORS:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=1000):
                await el.click()
                logger.info("Dismissed cookie banner via %s", sel)
                await asyncio.sleep(1)
                return
        except Exception:
            continue


async def login(context: BrowserContext, page: Page, cfg: NikeConfig) -> bool:
    """Log in to nike.com.br. Returns True on success.

    Flow: home → accept cookies → click "Entrar" → fill email → (continue) →
    fill password → submit.
    """
    if await is_logged_in(context):
        logger.info("Already logged in (cookies present)")
        return True

    logger.info("Navigating to home: %s", HOME_URL)
    await page.goto(HOME_URL, wait_until="domcontentloaded", timeout=60000)
    await asyncio.sleep(2)

    await _dismiss_cookie_banner(page)

    logger.info("Clicking Entrar (login link)")
    if not await _click_first_match(page, ENTRAR_LINK_SELECTORS):
        logger.error("Could not find Entrar link")
        await _debug_dump(page, "login-no-entrar")
        return False

    # Login form may be a modal, a new tab, or a redirect. Give it time.
    await asyncio.sleep(4)

    # If a new tab opened, switch to it
    if context.pages and context.pages[-1] is not page:
        page = context.pages[-1]
        logger.info("Switched to new tab: %s", page.url)

    logger.info("Now on: %s", page.url)

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

    # Wait for redirect away from login / modal to close
    await asyncio.sleep(5)

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
