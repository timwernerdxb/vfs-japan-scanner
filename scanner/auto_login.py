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
import base64
import logging
import os
import socket
import threading
from datetime import datetime
from urllib.parse import urlparse

from patchright.async_api import async_playwright

from scanner.captcha_solver import solve_turnstile

VFS_LOGIN_URL = "https://visa.vfsglobal.com/are/en/prt/login"

VFS_EMAIL = os.environ.get("VFS_EMAIL", "")
VFS_PASSWORD = os.environ.get("VFS_PASSWORD", "")
PROXY_ENABLED = os.environ.get("PROXY_ENABLED", "OFF").upper() == "ON"
PROXY_URL = os.environ.get("PROXY_URL", "")  # e.g. http://user:pass@host:port
# Or use separate env vars (takes priority if PROXY_SERVER is set):
PROXY_SERVER = os.environ.get("PROXY_SERVER", "")   # e.g. ae.decodo.com:20001
PROXY_USER = os.environ.get("PROXY_USER", "")
PROXY_PASS = os.environ.get("PROXY_PASS", "")

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


async def _log_page_debug(page, label="debug"):
    """Log page state for remote debugging."""
    try:
        url = page.url
        title = await page.title()
        logger.info("[%s] URL: %s | Title: %s", label, url, title)

        # Log a truncated base64 screenshot so we can decode it from Railway logs
        screenshot = await page.screenshot(type="png")
        b64 = base64.b64encode(screenshot).decode()
        # Log first 500 chars — enough to decode and inspect a small thumbnail
        logger.info("[%s] Screenshot (base64, first 500 chars): %s", label, b64[:500])

        # Log page HTML structure (just body tag children)
        structure = await page.evaluate("""
            () => {
                const body = document.body;
                if (!body) return 'no body';
                const tags = Array.from(body.children).map(
                    el => `<${el.tagName.toLowerCase()} id="${el.id}" class="${el.className}">`
                );
                return tags.join('\\n');
            }
        """)
        logger.info("[%s] Page structure:\n%s", label, structure)
    except Exception as e:
        logger.warning("[%s] Could not capture debug info: %s", label, e)


def _start_auth_proxy(upstream_host, upstream_port, username, password):
    """
    Start a local TCP proxy that injects Proxy-Authorization into CONNECT requests.

    Chromium expects a 407 challenge before sending auth, but some proxies reject
    immediately without auth. This local proxy adds the header proactively.
    Returns the local port number.
    """
    auth_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    local_port = srv.getsockname()[1]
    srv.listen(20)

    def _relay(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except Exception:
                    pass

    # Route these hosts through the upstream proxy.
    # Do NOT add challenges.cloudflare.com — Bright Data returns 402
    # "Residential Failed (bad_endpoint)" for CAPTCHA challenge domains.
    # Cloudflare challenges go DIRECT from Railway — this works fine now
    # that the Object.defineProperty hook is removed.
    PROXY_DOMAINS = (
        "visa.vfsglobal.com",
        "lift-api.vfsglobal.com",
    )

    def _handle(client):
        try:
            # Read initial request (e.g. CONNECT host:443 HTTP/1.1\r\n...\r\n\r\n)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                buf += chunk

            first_line = buf.split(b"\r\n")[0].decode(errors="replace")

            # Parse target from CONNECT request
            # Format: CONNECT host:port HTTP/1.1
            parts = first_line.split()
            target = parts[1] if len(parts) > 1 else ""
            target_host = target.split(":")[0]
            target_port = int(target.split(":")[1]) if ":" in target else 443

            use_proxy = target_host in PROXY_DOMAINS

            if use_proxy and buf.startswith(b"CONNECT"):
                logger.info("[local-proxy] PROXY %s", target)
                # Connect to upstream proxy
                upstream = socket.create_connection((upstream_host, upstream_port), timeout=15)

                # Inject Proxy-Authorization header
                idx = buf.index(b"\r\n\r\n")
                patched = (
                    buf[:idx]
                    + f"\r\nProxy-Authorization: Basic {auth_b64}".encode()
                    + buf[idx:]
                )
                upstream.sendall(patched)

                # Read proxy response
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = upstream.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                resp_line = resp.split(b"\r\n")[0].decode(errors="replace")
                logger.info("[local-proxy] Upstream: %s", resp_line)
                client.sendall(resp)

                if b" 200 " not in resp.split(b"\r\n")[0]:
                    logger.warning("[local-proxy] Tunnel rejected: %s", resp_line)
                    client.close()
                    upstream.close()
                    return
            elif buf.startswith(b"CONNECT"):
                # Direct connection — bypass proxy
                logger.info("[local-proxy] DIRECT %s", target)
                upstream = socket.create_connection((target_host, target_port), timeout=15)
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                # Non-CONNECT request — forward through proxy
                upstream = socket.create_connection((upstream_host, upstream_port), timeout=15)
                idx = buf.index(b"\r\n\r\n")
                patched = (
                    buf[:idx]
                    + f"\r\nProxy-Authorization: Basic {auth_b64}".encode()
                    + buf[idx:]
                )
                upstream.sendall(patched)

            # Bidirectional relay
            t1 = threading.Thread(target=_relay, args=(client, upstream), daemon=True)
            t2 = threading.Thread(target=_relay, args=(upstream, client), daemon=True)
            t1.start()
            t2.start()
            t1.join()
        except Exception as e:
            logger.warning("[local-proxy] Handler error: %s", e)
            try:
                client.close()
            except Exception:
                pass

    def _accept_loop():
        while True:
            try:
                client, _ = srv.accept()
                threading.Thread(target=_handle, args=(client,), daemon=True).start()
            except Exception:
                break

    threading.Thread(target=_accept_loop, daemon=True).start()
    logger.info("Local auth proxy started on 127.0.0.1:%d -> %s:%d", local_port, upstream_host, upstream_port)
    return local_port


def _test_proxy_connectivity():
    """Test proxy connectivity before launching browser."""
    import urllib.request

    if not PROXY_ENABLED or (not PROXY_SERVER and not PROXY_URL):
        return

    host = PROXY_SERVER.split("://")[-1].split(":")[0] if PROXY_SERVER else ""
    port_str = PROXY_SERVER.split(":")[-1] if PROXY_SERVER else ""
    if not host:
        return

    port = int(port_str) if port_str.isdigit() else 20004

    # Test 1: TCP connectivity
    logger.info("Testing TCP connectivity to %s:%d ...", host, port)
    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.close()
        logger.info("TCP connection to %s:%d OK", host, port)
    except Exception as e:
        logger.error("TCP connection to %s:%d FAILED: %s", host, port, e)
        return

    # Test 2: HTTP request through proxy
    logger.info("Testing HTTP request through proxy...")
    try:
        proxy_url = f"http://{PROXY_USER}:{PROXY_PASS}@{host}:{port}" if PROXY_USER else f"http://{host}:{port}"
        proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request("http://httpbin.org/ip", headers={"User-Agent": "Mozilla/5.0"})
        resp = opener.open(req, timeout=15)
        body = resp.read().decode()
        logger.info("Proxy HTTP test OK — response: %s", body.strip())
    except Exception as e:
        logger.warning("Proxy HTTP test failed: %s", e)

    # Test 3: HTTPS request through proxy (CONNECT tunnel)
    logger.info("Testing HTTPS CONNECT tunnel through proxy...")
    try:
        req_https = urllib.request.Request("https://httpbin.org/ip", headers={"User-Agent": "Mozilla/5.0"})
        resp_https = opener.open(req_https, timeout=15)
        body_https = resp_https.read().decode()
        logger.info("Proxy HTTPS tunnel OK — response: %s", body_https.strip())
    except Exception as e:
        logger.warning("Proxy HTTPS tunnel FAILED: %s", e)


async def _do_login() -> dict:
    """Perform a single login attempt. Returns session dict."""
    if not VFS_EMAIL or not VFS_PASSWORD:
        raise RuntimeError("VFS_EMAIL and VFS_PASSWORD environment variables required")

    # Test proxy connectivity before launching browser
    _test_proxy_connectivity()

    captured_headers = {}

    async with async_playwright() as p:
        launch_opts = dict(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-infobars",
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding",
            ],
        )
        # Configure proxy via local auth-injecting forwarder
        # Chromium doesn't send Proxy-Authorization proactively — some proxies
        # reject without a 407 challenge. Our local proxy fixes this.
        if PROXY_ENABLED and PROXY_SERVER:
            host = PROXY_SERVER.split("://")[-1].split(":")[0]
            port_str = PROXY_SERVER.split(":")[-1]
            port = int(port_str) if port_str.isdigit() else 20004
            local_port = _start_auth_proxy(host, port, PROXY_USER, PROXY_PASS)
            launch_opts["proxy"] = {"server": f"http://127.0.0.1:{local_port}"}
            logger.info("Proxy via local forwarder :%d -> %s:%d (user: %s)", local_port, host, port, PROXY_USER or "none")
        elif PROXY_ENABLED and PROXY_URL:
            parsed = urlparse(PROXY_URL)
            local_port = _start_auth_proxy(
                parsed.hostname, parsed.port or 20004,
                parsed.username or "", parsed.password or "",
            )
            launch_opts["proxy"] = {"server": f"http://127.0.0.1:{local_port}"}
            logger.info("Proxy via local forwarder :%d -> %s:%s", local_port, parsed.hostname, parsed.port)
        browser = await p.chromium.launch(**launch_opts)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            locale="en-US",
            timezone_id="Asia/Dubai",
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # Comprehensive anti-detection stealth patches
        await context.add_init_script("""
        () => {
            // Overwrite navigator.webdriver
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            // Chrome runtime
            window.chrome = {runtime: {}, loadTimes: function(){}, csi: function(){}};
            // Permissions
            const origQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (params) =>
                params.name === 'notifications'
                    ? Promise.resolve({state: Notification.permission})
                    : origQuery(params);
            // Plugins (non-empty array)
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            // Languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
            // Connection
            Object.defineProperty(navigator, 'connection', {
                get: () => ({rtt: 50, downlink: 10, effectiveType: '4g', saveData: false}),
            });
            // Hardware concurrency
            Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
            // Device memory
            Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
            // Platform
            Object.defineProperty(navigator, 'platform', {get: () => 'Linux x86_64'});

            // NON-INVASIVE Turnstile capture:
            // Do NOT use Object.defineProperty on window.turnstile — it blocks
            // Cloudflare's script from initializing. Instead, poll until
            // window.turnstile.render exists, then wrap it to capture sitekey.
            window.__capturedTurnstileSitekey = null;
            window.__turnstileCallback = null;
            window.__turnstileWidgetId = null;
            (function() {
                let wrapped = false;
                const poll = setInterval(() => {
                    if (window.turnstile && window.turnstile.render && !wrapped) {
                        wrapped = true;
                        const origRender = window.turnstile.render.bind(window.turnstile);
                        window.turnstile.render = function(container, options) {
                            if (options && options.sitekey) {
                                window.__capturedTurnstileSitekey = options.sitekey;
                                window.__turnstileCallback = options.callback || null;
                                console.log('TURNSTILE_SITEKEY_CAPTURED:' + options.sitekey);
                            }
                            const widgetId = origRender.apply(this, arguments);
                            window.__turnstileWidgetId = widgetId;
                            return widgetId;
                        };
                        console.log('TURNSTILE_RENDER_WRAPPED');
                        clearInterval(poll);
                    }
                }, 100);
                // Stop polling after 120s
                setTimeout(() => clearInterval(poll), 120000);
            })();
        }
        """)

        # Intercept requests to capture auth headers and Turnstile sitekey
        captured_turnstile_sitekey = {}

        async def on_request(request):
            url = request.url
            if "lift-api.vfsglobal.com" in url:
                headers = request.headers
                if headers.get("authorize") and not captured_headers.get("authorize"):
                    captured_headers["authorize"] = headers["authorize"]
                    captured_headers["clientsource"] = headers.get("clientsource", "")
                    logger.info("Captured authorize token from API request")
            # Log ALL Cloudflare requests to see if api.js is even fetched
            if "challenges.cloudflare.com" in url:
                logger.info("[request] %s %s", request.method, url[:120])
            # Capture Turnstile sitekey from challenge requests
            if "challenges.cloudflare.com" in url and "sitekey=" in url:
                import re
                m = re.search(r"sitekey=([^&]+)", url)
                if m and not captured_turnstile_sitekey.get("key"):
                    captured_turnstile_sitekey["key"] = m.group(1)
                    logger.info("Captured Turnstile sitekey from request URL: %s", m.group(1)[:12])

        page.on("request", on_request)

        # Monitor responses — especially Turnstile API script loading
        async def on_response(response):
            url = response.url
            if "challenges.cloudflare.com" in url:
                status = response.status
                ct = response.headers.get("content-type", "")
                logger.info("[response] %s — status=%d type=%s", url[:100], status, ct[:40])
                if "api.js" in url:
                    try:
                        body = await response.text()
                        logger.info("[response] api.js loaded — %d bytes, starts: %s", len(body), body[:80])
                    except Exception as e:
                        logger.warning("[response] api.js body read failed: %s", e)

        page.on("response", on_response)

        # Capture JS console messages (errors + Turnstile sitekey)
        js_errors = []

        def on_console(msg):
            text = msg.text
            if msg.type in ("error", "warning"):
                logger.info("[console.%s] %s", msg.type, text)
                js_errors.append(text)
            # Capture sitekey from our hook
            if "TURNSTILE_SITEKEY_CAPTURED:" in text:
                key = text.split("TURNSTILE_SITEKEY_CAPTURED:")[1].strip()
                captured_turnstile_sitekey["key"] = key
                logger.info("Captured Turnstile sitekey from console hook: %s...", key[:12])
            if "TURNSTILE_RENDER_WRAPPED" in text:
                logger.info("Turnstile render() successfully wrapped")

        page.on("console", on_console)

        try:
            # Navigate to login page
            logger.info("Navigating to VFS login page...")
            await page.goto(VFS_LOGIN_URL, wait_until="load", timeout=120000)

            # Check if VFS blocked us (redirects to page-not-found)
            if "page-not-found" in page.url:
                await _log_page_debug(page, "blocked")
                raise RuntimeError(
                    "VFS blocked the request (page-not-found). "
                    "IP may be rate-limited — will retry with backoff."
                )

            # Step 1: Handle Cloudflare Turnstile challenge
            # The Turnstile checkbox must be clicked before Angular bootstraps
            logger.info("Looking for Cloudflare Turnstile challenge...")
            for cf_attempt in range(3):
                try:
                    # Look for Turnstile iframe
                    cf_frame = page.frame_locator(
                        "iframe[src*='challenges.cloudflare.com'], "
                        "iframe[src*='turnstile']"
                    )
                    # Try to click the checkbox inside the iframe
                    checkbox = cf_frame.locator(
                        "input[type='checkbox'], "
                        ".cb-lb, "
                        "#challenge-stage, "
                        "label"
                    )
                    if await checkbox.count() > 0:
                        logger.info("Found Turnstile checkbox — clicking...")
                        await checkbox.first.click(timeout=5000)
                        logger.info("Clicked Turnstile checkbox")
                        await page.wait_for_timeout(5000)
                        break
                    else:
                        logger.info("No Turnstile checkbox found (attempt %d/3)", cf_attempt + 1)
                except Exception as e:
                    logger.info("Turnstile check %d/3: %s", cf_attempt + 1, e)
                await page.wait_for_timeout(3000)

            # Also try clicking any visible Turnstile widget in the main page
            try:
                turnstile_div = page.locator("[data-sitekey], .cf-turnstile, #cf-turnstile")
                if await turnstile_div.count() > 0:
                    logger.info("Found Turnstile widget — clicking...")
                    await turnstile_div.first.click()
                    await page.wait_for_timeout(5000)
            except Exception:
                pass

            # Step 2: Wait for Angular to bootstrap
            logger.info("Waiting for Angular to bootstrap...")
            for attempt_wait in range(18):  # Up to 180s total (18 x 10s)
                try:
                    await page.wait_for_selector(
                        "#mat-input-0, input[type='email'], app-login input, mat-form-field",
                        timeout=10000,
                    )
                    logger.info("Login form detected!")
                    break
                except Exception:
                    title = await page.title()
                    url = page.url
                    logger.info("Wait %d/12 — no form yet. URL: %s | Title: %s", attempt_wait + 1, url, title)
                    if "page-not-found" in url:
                        break

                    # Every 30s, try clicking Turnstile again
                    if (attempt_wait + 1) % 3 == 0:
                        try:
                            cf_frame = page.frame_locator("iframe[src*='challenges.cloudflare.com']")
                            checkbox = cf_frame.locator("input[type='checkbox'], .cb-lb, label")
                            if await checkbox.count() > 0:
                                await checkbox.first.click(timeout=3000)
                                logger.info("Re-clicked Turnstile checkbox")
                                await page.wait_for_timeout(5000)
                        except Exception:
                            pass
            else:
                logger.warning("Login form not found after 120s")
                await _log_page_debug(page, "form-not-found")

            # Debug: log page state
            page_title = await page.title()
            logger.info("Page loaded — URL: %s | Title: %s", page.url, page_title)

            if "page-not-found" in page.url or "unable to progress" in page_title.lower():
                await _log_page_debug(page, "blocked")
                raise RuntimeError(
                    "VFS blocked the request (page-not-found). "
                    "IP may be rate-limited — will retry with backoff."
                )

            # Dismiss cookie consent banner (OneTrust)
            # VFS uses OneTrust — must dismiss before form interaction
            logger.info("Dismissing cookie consent banner...")
            for sel in ["#onetrust-reject-all-handler", "#onetrust-accept-btn-handler"]:
                try:
                    btn = page.locator(sel)
                    await btn.wait_for(state="visible", timeout=5000)
                    await btn.click()
                    logger.info("Cookie banner dismissed via %s", sel)
                    await page.wait_for_timeout(1000)
                    break
                except Exception:
                    continue

            # Fill credentials first — Turnstile may render after form interaction
            logger.info("Filling login credentials...")

            # Try Angular Material selectors first, then generic fallbacks
            email_selectors = [
                "#mat-input-0",
                'input[type="email"]',
                'input[name="email"]',
                'input[placeholder*="mail"]',
                'input[id*="email"]',
            ]
            email_filled = False
            for sel in email_selectors:
                try:
                    locator = page.locator(sel)
                    await locator.wait_for(timeout=5000)
                    await locator.fill(VFS_EMAIL)
                    email_filled = True
                    logger.info("Email filled using selector: %s", sel)
                    break
                except Exception:
                    continue

            if not email_filled:
                # Debug: log what inputs are on the page
                input_info = await page.evaluate("""
                    () => {
                        const inputs = document.querySelectorAll('input');
                        return Array.from(inputs).map(i => ({
                            id: i.id, name: i.name, type: i.type,
                            placeholder: i.placeholder, class: i.className
                        }));
                    }
                """)
                logger.error("Available inputs on page: %s", input_info)
                await _log_page_debug(page, "email-not-found")
                raise RuntimeError("Could not find email input field")

            # Small pause after email fill — some forms reveal password after email
            await page.wait_for_timeout(2000)

            # Fill password — VFS is slow, so first wait for ANY password-like
            # input to appear (up to 30s), then try specific selectors quickly
            logger.info("Waiting for password field to appear...")
            try:
                await page.wait_for_selector(
                    'input[type="password"], input[placeholder*="assword"], '
                    'input[formcontrolname="password"], #mat-input-1',
                    timeout=30000,
                )
                logger.info("Password field appeared")
            except Exception:
                logger.warning("No password field after 30s — trying selectors anyway")

            password_selectors = [
                "#mat-input-1",
                'input[type="password"]',
                'input[name="password"]',
                'input[placeholder*="assword"]',
                'input[id*="password"]',
                'input[formcontrolname="password"]',
            ]
            password_filled = False
            for sel in password_selectors:
                try:
                    locator = page.locator(sel)
                    await locator.wait_for(timeout=3000)
                    await locator.fill(VFS_PASSWORD)
                    password_filled = True
                    logger.info("Password filled using selector: %s", sel)
                    break
                except Exception:
                    continue

            if not password_filled:
                # Debug: log what inputs are on the page
                input_info = await page.evaluate("""
                    () => {
                        const inputs = document.querySelectorAll('input, mat-form-field');
                        return Array.from(inputs).map(i => ({
                            tag: i.tagName, id: i.id, name: i.name,
                            type: i.type, placeholder: i.placeholder,
                            class: i.className, visible: i.offsetParent !== null
                        }));
                    }
                """)
                logger.error("Password not found! All inputs on page: %s", input_info)
                await _log_page_debug(page, "password-not-found")
                raise RuntimeError("Could not find password input field")

            # Solve Turnstile CAPTCHA via CapSolver
            # Strategy: quick poll for widget render, then fallback to searching
            # Angular bundles and manually fetching api.js if needed.
            logger.info("Waiting for Turnstile to initialize...")
            sitekey = None

            # Phase 1: Quick poll (30s) — check if widget renders naturally
            for ts_wait in range(10):  # 10 × 3s = 30s
                sitekey = await page.evaluate("""
                    () => {
                        if (window.__capturedTurnstileSitekey) return window.__capturedTurnstileSitekey;
                        const el = document.querySelector('.cf-turnstile, [data-sitekey]');
                        if (el && el.getAttribute('data-sitekey')) return el.getAttribute('data-sitekey');
                        const iframes = document.querySelectorAll('iframe');
                        for (const f of iframes) {
                            const m = f.src && f.src.match(/sitekey=([^&]+)/);
                            if (m) return m[1];
                        }
                        return null;
                    }
                """)
                if sitekey:
                    logger.info("Turnstile sitekey found (phase 1, attempt %d): %s...", ts_wait + 1, sitekey[:16])
                    break
                if captured_turnstile_sitekey.get("key"):
                    sitekey = captured_turnstile_sitekey["key"]
                    break
                if (ts_wait + 1) % 3 == 0:
                    ts_status = await page.evaluate("""
                        () => ({
                            turnstile: typeof window.turnstile,
                            iframes: document.querySelectorAll('iframe').length,
                        })
                    """)
                    logger.info("Turnstile phase 1 wait %d/10 — %s", ts_wait + 1, ts_status)
                await page.wait_for_timeout(3000)

            # Phase 2: Search Angular bundles for hardcoded sitekey
            if not sitekey:
                logger.info("Phase 2: Searching Angular bundles for sitekey...")
                sitekey = await page.evaluate("""
                    async () => {
                        // Search inline scripts
                        const scripts = document.querySelectorAll('script');
                        for (const s of scripts) {
                            if (s.textContent) {
                                const m = s.textContent.match(/sitekey['"]?\\s*[:=]\\s*['"]?(0x[a-fA-F0-9]+)/);
                                if (m) return m[1];
                            }
                        }

                        // Fetch and search Angular bundle files for sitekey
                        const scriptSrcs = Array.from(scripts)
                            .map(s => s.src)
                            .filter(s => s && (s.includes('main') || s.includes('app') || s.includes('chunk')));
                        for (const src of scriptSrcs) {
                            try {
                                const resp = await fetch(src);
                                const text = await resp.text();
                                // Look for Turnstile sitekey pattern (0x followed by hex)
                                const m = text.match(/['"]?(0x4AAA[a-zA-Z0-9_-]+)['"]?/);
                                if (m) return m[1];
                                // Broader pattern
                                const m2 = text.match(/sitekey['"]?\\s*[:=]\\s*['"]?(0x[a-fA-F0-9]+)/);
                                if (m2) return m2[1];
                                // Look for turnstile render call
                                const m3 = text.match(/turnstile.*?['"]?(0x[a-fA-F0-9]{8,})['"]?/);
                                if (m3) return m3[1];
                            } catch(e) {}
                        }

                        // Check environment/config objects
                        if (window.__env && window.__env.turnstileSitekey) return window.__env.turnstileSitekey;
                        if (window.__config && window.__config.turnstileSitekey) return window.__config.turnstileSitekey;

                        return null;
                    }
                """)
                if sitekey:
                    logger.info("Sitekey found in Angular bundle: %s...", sitekey[:16])

            # Phase 3: Manually fetch + eval api.js if turnstile still undefined
            if not sitekey:
                logger.info("Phase 3: Manually fetching and evaluating api.js...")
                eval_result = await page.evaluate("""
                    async () => {
                        try {
                            const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/api.js');
                            const status = resp.status;
                            const text = await resp.text();
                            const size = text.length;

                            // Check if the response looks like JavaScript
                            const isJS = text.trimStart().startsWith('(') ||
                                         text.trimStart().startsWith('/') ||
                                         text.trimStart().startsWith('!') ||
                                         text.trimStart().startsWith('var') ||
                                         text.trimStart().startsWith('window');

                            if (status === 200 && isJS && size > 100) {
                                // Eval the script to create window.turnstile
                                eval(text);
                                return {
                                    status: status,
                                    size: size,
                                    turnstileAfterEval: typeof window.turnstile,
                                    start: text.substring(0, 100)
                                };
                            }
                            return {
                                status: status,
                                size: size,
                                isJS: isJS,
                                start: text.substring(0, 200)
                            };
                        } catch(e) {
                            return {error: e.message};
                        }
                    }
                """)
                logger.info("Manual api.js fetch result: %s", eval_result)

                # If eval worked, check for turnstile and try to get sitekey
                if eval_result and eval_result.get("turnstileAfterEval") == "object":
                    logger.info("Turnstile initialized via manual eval! Waiting for render...")
                    # Wait for VFS to call render (now that turnstile exists)
                    for post_wait in range(10):
                        sitekey = await page.evaluate("""
                            () => window.__capturedTurnstileSitekey
                        """)
                        if sitekey:
                            logger.info("Sitekey captured after manual eval: %s...", sitekey[:16])
                            break
                        if captured_turnstile_sitekey.get("key"):
                            sitekey = captured_turnstile_sitekey["key"]
                            break
                        await page.wait_for_timeout(3000)

            # Phase 4: Last resort — look for sitekey in page HTML source
            if not sitekey:
                logger.info("Phase 4: Searching full page HTML for sitekey...")
                sitekey = await page.evaluate("""
                    () => {
                        const html = document.documentElement.outerHTML;
                        // Look for any 0x-prefixed hex string that looks like a sitekey
                        const m = html.match(/0x4AAA[a-zA-Z0-9_-]{20,}/);
                        if (m) return m[0];
                        const m2 = html.match(/0x[0-9a-fA-F]{22,}/);
                        if (m2) return m2[0];
                        return null;
                    }
                """)
                if sitekey:
                    logger.info("Sitekey found in page HTML: %s...", sitekey[:16])

            if not sitekey:
                logger.warning("All 4 phases failed — no Turnstile sitekey found")

            if sitekey:
                try:
                    logger.info("Requesting CapSolver to solve Turnstile...")
                    token = solve_turnstile(VFS_LOGIN_URL, sitekey)
                    logger.info("Turnstile solved! Token length: %d", len(token))

                    # Inject token via the hooked callback (enables the button)
                    await page.evaluate("""
                        (token) => {
                            // Method 1: Call the captured callback
                            if (window.__turnstileCallback) {
                                window.__turnstileCallback(token);
                            }
                            // Method 2: Set hidden input values
                            const inputs = [
                                document.querySelector('[name="cf-turnstile-response"]'),
                                document.querySelector('[name="g-recaptcha-response"]'),
                            ];
                            for (const input of inputs) {
                                if (input) input.value = token;
                            }
                            // Method 3: Try turnstile global callbacks
                            if (window.turnstile && window.__turnstileWidgetId !== null) {
                                // Some implementations check getResponse
                            }
                        }
                    """, token)
                    logger.info("Turnstile token injected")
                    await page.wait_for_timeout(3000)
                except Exception as e:
                    logger.warning("CapSolver Turnstile solve failed: %s", e)
            else:
                logger.warning("No Turnstile sitekey found — button may stay disabled")

            # Click Sign In button
            logger.info("Looking for Sign In button...")
            sign_in = page.locator('button[type="submit"]:has-text("Sign In")')
            try:
                await sign_in.wait_for(state="attached", timeout=60000)
                logger.info("Sign In button found in DOM")
            except Exception:
                sign_in = page.locator('button:has-text("Sign In")')
                try:
                    await sign_in.wait_for(state="attached", timeout=30000)
                    logger.info("Sign In button found (broad selector)")
                except Exception:
                    logger.error("Sign In button not found on page")
                    await _log_page_debug(page, "submit-not-found")
                    raise RuntimeError("Could not find submit button")

            # Check if button is enabled (Turnstile token should have enabled it)
            is_disabled = await sign_in.is_disabled()
            if is_disabled:
                logger.info("Sign In button still disabled — waiting up to 30s...")
                for wait_i in range(6):  # 6 × 5s = 30s
                    await page.wait_for_timeout(5000)
                    if not await sign_in.is_disabled():
                        logger.info("Sign In button is now enabled!")
                        break
                    logger.info("Still disabled (%d/6)...", wait_i + 1)
                else:
                    logger.warning("Force-enabling Sign In button")
                    await page.evaluate("""
                        () => {
                            const btn = document.querySelector('button[type="submit"]');
                            if (btn) {
                                btn.disabled = false;
                                btn.classList.remove('mat-mdc-button-disabled');
                            }
                        }
                    """)
                    await page.wait_for_timeout(500)
            else:
                logger.info("Sign In button is enabled!")

            await sign_in.click(force=True)
            logger.info("Clicked Sign In button")

            # Wait for post-login page (dashboard or "Start New Booking" button)
            logger.info("Waiting for post-login page...")
            try:
                await page.wait_for_url("**/dashboard", timeout=30000)
                logger.info("Dashboard loaded — login successful!")
            except Exception:
                # VFS might show "Start New Booking" instead of redirecting to /dashboard
                try:
                    start_booking = page.get_by_role("button", name="Start New Booking")
                    await start_booking.wait_for(timeout=10000)
                    logger.info("Post-login page loaded (Start New Booking visible)")
                except Exception:
                    current_url = page.url
                    logger.warning("Did not reach dashboard. Current URL: %s", current_url)
                    await _log_page_debug(page, "post-login-fail")
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
