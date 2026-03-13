"""
Automated VFS Global login using Playwright + CapSolver.

Handles the full login flow:
1. Launch headless Chromium
2. Navigate to VFS login page
3. Solve Cloudflare Turnstile via CapSolver
4. Fill email/password and submit
5. Extract JWT, cookies, and clientsource
6. Return session dict for use with vfs_checker
"""

import asyncio
import logging
import os
from datetime import datetime

from playwright.async_api import async_playwright

from scanner.captcha_solver import solve_turnstile

VFS_LOGIN_URL = "https://visa.vfsglobal.com/are/en/prt/login"

VFS_EMAIL = os.environ.get("VFS_EMAIL", "")
VFS_PASSWORD = os.environ.get("VFS_PASSWORD", "")

logger = logging.getLogger("auto_login")


async def _extract_turnstile_sitekey(page) -> str:
    """Extract the Cloudflare Turnstile sitekey from the page."""
    sitekey = await page.evaluate("""
        () => {
            // Method 1: data-sitekey attribute
            const el = document.querySelector('[data-sitekey]');
            if (el) return el.getAttribute('data-sitekey');

            // Method 2: Turnstile iframe src
            const iframe = document.querySelector('iframe[src*="turnstile"]');
            if (iframe) {
                const match = iframe.src.match(/sitekey=([^&]+)/);
                if (match) return match[1];
            }

            // Method 3: Search scripts for sitekey
            const scripts = document.querySelectorAll('script');
            for (const s of scripts) {
                if (s.textContent) {
                    const m = s.textContent.match(/sitekey['"]?\\s*[:=]\\s*['"]?(0x[a-fA-F0-9]+)/);
                    if (m) return m[1];
                }
            }

            return null;
        }
    """)

    if not sitekey:
        # Fallback: check env var
        sitekey = os.environ.get("VFS_TURNSTILE_SITEKEY", "")

    if not sitekey:
        raise RuntimeError("Could not find Turnstile sitekey on page")

    logger.info("Found Turnstile sitekey: %s...", sitekey[:12])
    return sitekey


async def _inject_turnstile_token(page, token: str):
    """Inject a solved Turnstile token into the page."""
    await page.evaluate("""
        (token) => {
            // Set hidden input values
            const inputs = [
                document.querySelector('[name="cf-turnstile-response"]'),
                document.querySelector('[name="g-recaptcha-response"]'),
            ];
            for (const input of inputs) {
                if (input) input.value = token;
            }

            // Try to trigger the Turnstile callback
            const widgets = document.querySelectorAll('[data-sitekey]');
            for (const w of widgets) {
                const callbackName = w.getAttribute('data-callback');
                if (callbackName && typeof window[callbackName] === 'function') {
                    window[callbackName](token);
                }
            }

            // Also try the global turnstile callback pattern
            if (window._turnstileCb) {
                window._turnstileCb(token);
            }
        }
    """, token)
    logger.info("Turnstile token injected")


async def _do_login() -> dict:
    """Perform a single login attempt. Returns session dict."""
    if not VFS_EMAIL or not VFS_PASSWORD:
        raise RuntimeError("VFS_EMAIL and VFS_PASSWORD environment variables required")

    captured_headers = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
        )
        page = await context.new_page()

        # Anti-detection: remove webdriver flag
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        """)

        # Intercept API requests to capture auth headers
        async def on_request(request):
            if "lift-api.vfsglobal.com" in request.url:
                headers = request.headers
                if headers.get("authorize") and not captured_headers.get("authorize"):
                    captured_headers["authorize"] = headers["authorize"]
                    captured_headers["clientsource"] = headers.get("clientsource", "")
                    logger.info("Captured authorize token from API request")

        page.on("request", on_request)

        try:
            # Navigate to login page
            logger.info("Navigating to VFS login page...")
            await page.goto(VFS_LOGIN_URL, wait_until="networkidle", timeout=60000)
            await page.wait_for_timeout(3000)

            # Solve Turnstile
            try:
                sitekey = await _extract_turnstile_sitekey(page)
                token = solve_turnstile(VFS_LOGIN_URL, sitekey)
                await _inject_turnstile_token(page, token)
                await page.wait_for_timeout(2000)
            except Exception as e:
                logger.warning("Turnstile solving failed: %s — trying to proceed anyway", e)

            # Fill credentials
            logger.info("Filling login credentials...")

            # Try multiple selector patterns for email
            email_selectors = [
                'input[type="email"]',
                'input[name="email"]',
                'input[placeholder*="mail"]',
                'input[id*="email"]',
            ]
            email_filled = False
            for sel in email_selectors:
                try:
                    await page.wait_for_selector(sel, timeout=5000)
                    await page.fill(sel, VFS_EMAIL)
                    email_filled = True
                    logger.info("Email filled using selector: %s", sel)
                    break
                except Exception:
                    continue

            if not email_filled:
                raise RuntimeError("Could not find email input field")

            # Fill password
            password_selectors = [
                'input[type="password"]',
                'input[name="password"]',
                'input[id*="password"]',
            ]
            password_filled = False
            for sel in password_selectors:
                try:
                    await page.fill(sel, VFS_PASSWORD)
                    password_filled = True
                    logger.info("Password filled using selector: %s", sel)
                    break
                except Exception:
                    continue

            if not password_filled:
                raise RuntimeError("Could not find password input field")

            # Click sign in
            submit_selectors = [
                'button[type="submit"]',
                'button:has-text("Sign In")',
                'button:has-text("Login")',
                'button:has-text("Log In")',
                '.btn-sign-in',
            ]
            submitted = False
            for sel in submit_selectors:
                try:
                    await page.click(sel, timeout=5000)
                    submitted = True
                    logger.info("Clicked submit using selector: %s", sel)
                    break
                except Exception:
                    continue

            if not submitted:
                raise RuntimeError("Could not find submit button")

            # Wait for dashboard
            logger.info("Waiting for dashboard...")
            try:
                await page.wait_for_url("**/dashboard", timeout=30000)
                logger.info("Dashboard loaded — login successful!")
            except Exception:
                current_url = page.url
                logger.warning("Did not reach dashboard. Current URL: %s", current_url)
                # Try to continue anyway — maybe the URL pattern is different
                if "login" in current_url:
                    raise RuntimeError(f"Still on login page: {current_url}")

            await page.wait_for_timeout(3000)

            # Extract JWT from storage
            jwt = await page.evaluate("""
                window.sessionStorage.getItem('JWT')
                || window.localStorage.getItem('JWT')
                || ''
            """)

            if not jwt:
                # Search for EAAAA-prefixed tokens
                jwt = await page.evaluate("""
                    (() => {
                        const stores = [sessionStorage, localStorage];
                        for (const s of stores) {
                            for (let i = 0; i < s.length; i++) {
                                const val = s.getItem(s.key(i));
                                if (val && val.indexOf('EAAAA') === 0) return val;
                            }
                        }
                        return '';
                    })()
                """)

            # Use header-intercepted token as fallback
            if not jwt and captured_headers.get("authorize"):
                jwt = captured_headers["authorize"]
                logger.info("Using authorize token from intercepted API request")

            if not jwt:
                raise RuntimeError("Could not capture JWT token")

            logger.info("JWT captured (length: %d)", len(jwt))

            # Extract cookies
            cookies = await context.cookies()
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)

            cf_clearance = ""
            for c in cookies:
                if c["name"] == "cf_clearance":
                    cf_clearance = c["value"]

            # Get user agent
            user_agent = await page.evaluate("navigator.userAgent")

            # Extract login email from storage
            login_user = await page.evaluate("""
                window.sessionStorage.getItem('loginUser')
                || window.sessionStorage.getItem('email')
                || window.localStorage.getItem('loginUser')
                || window.localStorage.getItem('email')
                || ''
            """) or VFS_EMAIL

            session = {
                "authorize": jwt,
                "cookies": cookie_str,
                "login_user": login_user,
                "user_agent": user_agent,
                "cf_clearance": cf_clearance,
                "captured_at": datetime.now().isoformat(),
            }

            if captured_headers.get("clientsource"):
                session["clientsource"] = captured_headers["clientsource"]

            # If we still need clientsource, trigger an API call
            if not session.get("clientsource"):
                logger.info("Navigating to appointment page to capture clientsource...")
                try:
                    await page.goto(
                        "https://visa.vfsglobal.com/are/en/prt/application-detail",
                        timeout=15000,
                    )
                    await page.wait_for_timeout(5000)
                    if captured_headers.get("clientsource"):
                        session["clientsource"] = captured_headers["clientsource"]
                except Exception:
                    logger.warning("Could not capture clientsource — continuing without it")

            return session

        finally:
            await browser.close()


async def auto_login(max_retries: int = 3) -> dict:
    """
    Perform automated VFS login with retries.

    Returns a session dict compatible with vfs_checker.check_slot().
    Raises RuntimeError if all retries fail.
    """
    for attempt in range(max_retries):
        try:
            session = await _do_login()
            if session.get("authorize"):
                logger.info("Login successful on attempt %d/%d", attempt + 1, max_retries)
                return session
            raise RuntimeError("No JWT captured")
        except Exception as e:
            logger.warning("Login attempt %d/%d failed: %s", attempt + 1, max_retries, e)
            if attempt < max_retries - 1:
                wait = 30 * (attempt + 1)
                logger.info("Retrying in %ds...", wait)
                await asyncio.sleep(wait)

    raise RuntimeError(f"Login failed after {max_retries} attempts")
