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
    'header a:text-is("Entrar")',
    'nav a:text-is("Entrar")',
    'a:text-is("Entrar")',
    'header a:text-is("ENTRAR")',
    'a:text-is("ENTRAR")',
    'header button:text-is("Entrar")',
    'button:text-is("Entrar")',
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
    'button:has-text("ENTRAR"):not(:has-text("código")):not([disabled])',
    'button:has-text("Entrar"):not(:has-text("código")):not([disabled])',
    'button:has-text("Continuar"):not([disabled])',
    'button:has-text("SIGN IN"):not([disabled])',
    'button[data-testid="submit-button"]',
]

USE_PASSWORD_SELECTORS = [
    'button:has-text("Usar a senha")',
    'button:has-text("USAR A SENHA")',
    'a:has-text("Usar a senha")',
    'button:has-text("Use password")',
]

OTP_INPUT_SELECTORS = [
    'input[name="code"]',
    'input[name="otp"]',
    'input[name="verificationCode"]',
    'input[autocomplete="one-time-code"]',
    'input[placeholder*="código" i]',
    'input[placeholder*="dígitos" i]',
    'input[inputmode="numeric"]',
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

    # Nike's login has three possible initial states:
    #   (a) password field already visible (saved session, direct password)
    #   (b) email input (first-time or after logout)
    #   (c) "Continuar como <email>" card (email remembered)
    password_visible = False
    for sel in PASSWORD_SELECTORS:
        try:
            if await page.locator(sel).first.is_visible(timeout=1000):
                password_visible = True
                break
        except Exception:
            continue

    if password_visible:
        logger.info("Password field visible — skipping email step")
    else:
        email_filled = await _fill_first_match(page, EMAIL_SELECTORS, cfg.email)
        if email_filled:
            await _click_first_match(page, SUBMIT_SELECTORS)
            await asyncio.sleep(3)
        else:
            logger.info("No email input — trying Continuar (saved-email flow)")
            continue_selectors = [
                'button:has-text("Continuar"):not([disabled])',
                'button:has-text("CONTINUAR"):not([disabled])',
                f'button:has-text("{cfg.email}")',
            ]
            if not await _click_first_match(page, continue_selectors):
                logger.error("Could not find email field or Continuar button")
                await _debug_dump(page, "login-no-email")
                return False
            await asyncio.sleep(3)

    # Nike defaults to 8-digit email code — switch to password login
    if await _click_first_match(page, USE_PASSWORD_SELECTORS):
        logger.info("Switched to password login")
        await asyncio.sleep(2)
    else:
        logger.info("No 'Usar a senha' button — assuming password form is already shown")

    if not await _fill_first_match(page, PASSWORD_SELECTORS, cfg.password):
        logger.error("Could not find password field")
        await _debug_dump(page, "login-no-password")
        return False

    await _click_first_match(page, SUBMIT_SELECTORS)
    await asyncio.sleep(5)

    # Handle one-time-code challenge (Nike triggers this after repeated
    # failed logins or from a new device). Prompt the user interactively.
    if await _handle_otp_challenge(page, cfg):
        await asyncio.sleep(5)

    if await is_logged_in(context):
        logger.info("Login successful")
        return True

    logger.error("Login did not produce auth cookies")
    await _debug_dump(page, "login-failed")
    return False


async def _handle_otp_challenge(page: Page, cfg: NikeConfig) -> bool:
    """If an OTP input is shown, prompt the user to enter the code.

    Returns True if we handled an OTP (regardless of success), False if
    no OTP screen was detected.
    """
    import os
    import sys

    otp_visible = False
    for sel in OTP_INPUT_SELECTORS:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=1500):
                otp_visible = True
                break
        except Exception:
            continue

    if not otp_visible:
        return False

    logger.warning(
        "Nike is asking for a verification code. Check your email for the "
        "8-digit code."
    )

    if not sys.stdin.isatty():
        env_code = os.environ.get("NIKE_OTP_CODE", "").strip()
        if env_code:
            logger.info("Using NIKE_OTP_CODE from env")
            code = env_code
        else:
            logger.error(
                "OTP required but no TTY and NIKE_OTP_CODE not set. "
                "Run interactively to enter the code, or set NIKE_OTP_CODE."
            )
            return True
    else:
        code = await asyncio.to_thread(
            input, "Enter the 8-digit code from your email and press Enter: "
        )
        code = code.strip()

    if not code:
        logger.error("No OTP code provided")
        return True

    for sel in OTP_INPUT_SELECTORS:
        try:
            el = page.locator(sel).first
            await el.wait_for(state="visible", timeout=1500)
            await el.fill(code)
            logger.info("Filled OTP code")
            break
        except Exception:
            continue

    await _click_first_match(page, SUBMIT_SELECTORS)
    return True


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
