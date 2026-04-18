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


# Exact names for cookies Nike sets only when actually authenticated.
# 'auth', 'sso' etc. were too broad and matched anonymous tracking cookies.
AUTH_COOKIE_NAMES = {
    "anonymousId",  # set even when anonymous — NOT auth
}
# Prefixes that DO indicate an authenticated session on nike.com.br.
AUTH_COOKIE_PREFIXES = ("nike-auth", "ni_auth", "nss-", "__cf_bm_auth", "id_token", "access_token", "idtoken", "accesstoken")


async def is_logged_in(context: BrowserContext, page: Page | None = None) -> bool:
    """Ground-truth check: hit /minha-conta (account page). If we land on
    an account page we're logged in; if Nike redirects to the login screen
    we're not. Cookie-name heuristics were unreliable — Nike sets many
    'auth*' / 'sso*' named tracking cookies even for anonymous visitors.
    """
    if page is None:
        # Fall back to cookie sniffing only if no page was provided.
        cookies = await context.cookies()
        for c in cookies:
            name = c["name"]
            if any(name.lower().startswith(p) for p in AUTH_COOKIE_PREFIXES):
                return True
        return False
    try:
        await page.goto(
            "https://www.nike.com.br/minha-conta",
            wait_until="domcontentloaded",
            timeout=20000,
        )
        # Give the SPA a moment to render its auth-gated UI.
        await asyncio.sleep(2)
        final = page.url.lower()
        if "login" in final or "signin" in final:
            logger.info("Account page redirected to login (%s) — not logged in", final)
            return False
        # Look for login-form inputs (strong anonymous signal).
        has_pw = await page.locator('input[type="password"]').count() > 0
        if has_pw:
            logger.info("Password input present on /minha-conta — not logged in")
            return False
        # Look for logged-in-only indicators.
        logged_in_signals = [
            'text=/Meus pedidos/i',
            'text=/Minhas compras/i',
            'text=/Meus dados/i',
            'text=/^Olá/i',
            'button:has-text("Sair"):not([aria-hidden])',
            'a:has-text("Sair")',
        ]
        for sel in logged_in_signals:
            try:
                if await page.locator(sel).first.is_visible(timeout=500):
                    logger.info("Logged-in signal visible (%s)", sel)
                    return True
            except Exception:
                continue
        # Look for anonymous-user CTAs.
        anon_signals = [
            'text=/Fazer login/i',
            'text=/Entrar com senha/i',
            'button:has-text("Entrar")',
            'a:has-text("Cadastre-se")',
        ]
        for sel in anon_signals:
            try:
                if await page.locator(sel).first.is_visible(timeout=500):
                    logger.info("Anon signal visible (%s) — not logged in", sel)
                    return False
            except Exception:
                continue
        logger.info("Probe unclear at %s — treating as NOT logged in", final)
        return False
    except Exception as e:
        logger.warning("is_logged_in probe failed (%s) — assuming NOT logged in", e)
        return False


async def login(context: BrowserContext, page: Page, cfg: NikeConfig) -> bool:
    """Ensure we're logged in. Returns True once auth cookies are present."""
    if await is_logged_in(context, page):
        logger.info("Already logged in")
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
    interval = 5
    while elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval
        # Don't hijack the user's current page if they're mid-login on an
        # IdP (e.g. login.gruposbf.com.br keycloak realm).
        cur_url = (page.url or "").lower()
        mid_login = any(
            k in cur_url
            for k in ("login.gruposbf", "gruposbf", "keycloak", "openid", "authorize", "/login")
        )
        if mid_login:
            logger.info("Waiting... (%ds) — user still on login page %s", elapsed, cur_url[:80])
            continue
        # On every tick, cheap cookie-prefix sniff; probe the account page
        # every 20s to confirm.
        if elapsed % 20 == 0:
            if await is_logged_in(context, page):
                logger.info("Login detected after %ds — continuing", elapsed)
                return True
            logger.info("Still waiting for login... (%ds / %ds)", elapsed, timeout)

    logger.error("Timed out waiting for manual login")
    return False
