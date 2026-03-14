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

            // IMMUTABLE FAKE TURNSTILE: Cloudflare's api.js actively removes
            // window.turnstile in headless. Using Object.defineProperty with
            // configurable:false makes it impossible for CF to delete/overwrite.
            // NOTE: This is NOT the old getter/setter approach that broke things.
            // We're setting a REAL object, just making the property immutable.
            window.__capturedTurnstileSitekey = null;
            window.__turnstileCallback = null;
            window.__turnstileWidgetId = null;
            window.__allTurnstileCallbacks = [];

            const _fakeTurnstile = {
                render: function(container, options) {
                    console.log('FAKE_TURNSTILE_RENDER called with container=' +
                                (typeof container === 'string' ? container : container?.id || 'element'));
                    if (options) {
                        console.log('FAKE_TURNSTILE_RENDER options keys: ' +
                                    Object.keys(options).join(','));
                        if (options.sitekey) {
                            window.__capturedTurnstileSitekey = options.sitekey;
                            console.log('TURNSTILE_SITEKEY_CAPTURED:' + options.sitekey);
                        }
                        if (options.callback) {
                            window.__turnstileCallback = options.callback;
                            window.__allTurnstileCallbacks.push(options.callback);
                            console.log('TURNSTILE_CALLBACK_CAPTURED (type=' +
                                        typeof options.callback + ')');
                        }
                        // VFS may pass 'error-callback' or 'expired-callback'
                        if (options['error-callback']) {
                            console.log('TURNSTILE has error-callback');
                        }
                        if (options['expired-callback']) {
                            console.log('TURNSTILE has expired-callback');
                        }
                    }
                    window.__turnstileWidgetId = 'fake-widget-0';
                    return 'fake-widget-0';
                },
                getResponse: function(id) { return ''; },
                reset: function(id) { console.log('FAKE_TURNSTILE_RESET'); },
                remove: function(id) { console.log('FAKE_TURNSTILE_REMOVE'); },
                isExpired: function(id) { return false; },
                execute: function(container, options) {
                    console.log('FAKE_TURNSTILE_EXECUTE called');
                    if (options && options.callback) {
                        window.__turnstileCallback = options.callback;
                        window.__allTurnstileCallbacks.push(options.callback);
                        console.log('TURNSTILE_CALLBACK_CAPTURED via execute');
                    }
                    return 'fake-widget-0';
                },
                ready: function(cb) {
                    // Some implementations call turnstile.ready(callback)
                    console.log('FAKE_TURNSTILE_READY called');
                    if (typeof cb === 'function') cb();
                },
                __isFake: true
            };

            // Lock it down — Cloudflare can't delete or overwrite
            Object.defineProperty(window, 'turnstile', {
                value: _fakeTurnstile,
                writable: false,
                configurable: false,
                enumerable: true
            });
            console.log('FAKE_TURNSTILE installed (immutable via defineProperty)');

            // Also watch for Angular's Turnstile component loading via script tag
            // Some Angular wrappers listen for the script's onload event
            const observer = new MutationObserver((mutations) => {
                for (const m of mutations) {
                    for (const node of m.addedNodes) {
                        if (node.tagName === 'SCRIPT' && node.src &&
                            node.src.includes('challenges.cloudflare.com')) {
                            console.log('TURNSTILE_SCRIPT_ADDED: ' + node.src);
                            // Fire load event so Angular wrappers think script loaded
                            setTimeout(() => {
                                node.dispatchEvent(new Event('load'));
                                console.log('TURNSTILE_SCRIPT_LOAD_FIRED');
                            }, 1000);
                        }
                    }
                }
            });
            observer.observe(document.documentElement, {childList: true, subtree: true});
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
            # Sitekey appears in URL PATH like: /turnstile/f/.../0x4AAAA.../
            # or as query param: sitekey=0x4AAAA...
            if "challenges.cloudflare.com" in url:
                import re
                # Path pattern: /0x followed by hex/alphanumeric
                m = re.search(r"/(0x4[a-zA-Z0-9_-]{10,})/?", url)
                if not m:
                    m = re.search(r"sitekey=([^&]+)", url)
                if m and not captured_turnstile_sitekey.get("key"):
                    captured_turnstile_sitekey["key"] = m.group(1)
                    logger.info("Captured Turnstile sitekey from request URL: %s", m.group(1))

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
            # Log ALL our fake turnstile messages
            if text.startswith("FAKE_TURNSTILE") or text.startswith("TURNSTILE_"):
                logger.info("[console] %s", text)
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
            # The sitekey is captured from Cloudflare network requests (URL path
            # contains /0x4AAAA.../). Wait briefly for it, then try DOM + iframe.
            logger.info("Waiting for Turnstile sitekey from network/DOM...")
            sitekey = None

            for ts_wait in range(20):  # 20 × 3s = 60s max
                # Check network capture (most reliable — sitekey in URL path)
                if captured_turnstile_sitekey.get("key"):
                    sitekey = captured_turnstile_sitekey["key"]
                    logger.info("Sitekey from network capture: %s", sitekey)
                    break
                # Check DOM / init script hook
                sitekey = await page.evaluate("""
                    () => {
                        if (window.__capturedTurnstileSitekey) return window.__capturedTurnstileSitekey;
                        const el = document.querySelector('.cf-turnstile, [data-sitekey]');
                        if (el && el.getAttribute('data-sitekey')) return el.getAttribute('data-sitekey');
                        // Check Turnstile iframes for sitekey in src
                        const iframes = document.querySelectorAll('iframe');
                        for (const f of iframes) {
                            if (f.src) {
                                let m = f.src.match(/sitekey=([^&]+)/);
                                if (m) return m[1];
                                m = f.src.match(/\\/(0x4[a-zA-Z0-9_-]{10,})\\/?/);
                                if (m) return m[1];
                            }
                        }
                        return null;
                    }
                """)
                if sitekey:
                    logger.info("Sitekey from DOM (attempt %d): %s", ts_wait + 1, sitekey)
                    break
                if (ts_wait + 1) % 5 == 0:
                    logger.info("Sitekey wait %d/20 — not found yet", ts_wait + 1)
                await page.wait_for_timeout(3000)

            # Fallback: env var or hardcoded (sitekeys rarely change)
            if not sitekey:
                sitekey = os.environ.get("VFS_TURNSTILE_SITEKEY", "")
                if sitekey:
                    logger.info("Using sitekey from env var: %s", sitekey)

            if not sitekey:
                logger.warning("No Turnstile sitekey found from any source")

            token = ""  # Will be set if sitekey found and CapSolver succeeds
            if sitekey:
                try:
                    # Check if our fake turnstile captured the callback
                    callback_status = await page.evaluate("""
                        () => ({
                            hasCallback: !!window.__turnstileCallback,
                            callbackType: typeof window.__turnstileCallback,
                            totalCallbacks: window.__allTurnstileCallbacks ? window.__allTurnstileCallbacks.length : 0,
                            capturedSitekey: window.__capturedTurnstileSitekey,
                            widgetId: window.__turnstileWidgetId,
                            turnstileExists: !!window.turnstile,
                        })
                    """)
                    logger.info("Fake turnstile status: %s", callback_status)

                    logger.info("Requesting CapSolver to solve Turnstile...")
                    token = solve_turnstile(VFS_LOGIN_URL, sitekey)
                    logger.info("Turnstile solved! Token length: %d", len(token))

                    # Inject token into Angular's reactive form system
                    # From bundle analysis: the login form uses FormGroup with controls:
                    #   username, password, captcha_api_key, captcha_version
                    # Button disabled = loginForm.invalid
                    # We need to patch captcha_api_key + captcha_version to make form valid
                    inject_result = await page.evaluate("""
                        (token) => {
                            const results = [];

                            // === PRIMARY: Patch Angular FormGroup via __ngContext__ ===
                            // Walk all DOM elements to find the login component
                            let loginFormGroup = null;
                            let loginComponent = null;
                            const allElements = document.querySelectorAll('*');

                            for (const el of allElements) {
                                const ctx = el.__ngContext__;
                                if (!ctx) continue;

                                // __ngContext__ can be array (LView) or number (index)
                                const items = Array.isArray(ctx) ? ctx : [];
                                for (const item of items) {
                                    if (!item || typeof item !== 'object') continue;

                                    // Look for component with loginForm property
                                    if (item.loginForm && item.loginForm.controls) {
                                        loginComponent = item;
                                        loginFormGroup = item.loginForm;
                                        results.push('FOUND_LOGIN_COMPONENT');
                                        break;
                                    }

                                    // Or find FormGroup with username + password controls
                                    if (item.controls && item.controls.username &&
                                        item.controls.password) {
                                        loginFormGroup = item;
                                        results.push('FOUND_FORM_GROUP_DIRECT');
                                        break;
                                    }
                                }
                                if (loginFormGroup) break;
                            }

                            if (loginFormGroup) {
                                const controlNames = Object.keys(loginFormGroup.controls);
                                results.push('form_controls:' + controlNames.join(','));

                                // Set captcha_api_key (the CAPTCHA token field)
                                if (loginFormGroup.controls.captcha_api_key) {
                                    loginFormGroup.controls.captcha_api_key.setValue(token);
                                    loginFormGroup.controls.captcha_api_key.markAsDirty();
                                    loginFormGroup.controls.captcha_api_key.markAsTouched();
                                    // Clear required validator so form becomes valid
                                    if (loginFormGroup.controls.captcha_api_key.clearValidators) {
                                        loginFormGroup.controls.captcha_api_key.clearValidators();
                                    }
                                    loginFormGroup.controls.captcha_api_key.updateValueAndValidity();
                                    results.push('SET_captcha_api_key');
                                } else {
                                    // Control doesn't exist yet — try patchValue (ignores missing)
                                    try {
                                        loginFormGroup.patchValue({ captcha_api_key: token });
                                        results.push('PATCHED_captcha_api_key');
                                    } catch(e) { results.push('patch_error:' + e.message); }
                                }

                                // Set captcha_version
                                if (loginFormGroup.controls.captcha_version) {
                                    // Try to get the correct version string from the component
                                    let version = 'Turnstile';
                                    if (loginComponent && loginComponent.captchaVersionConst) {
                                        // captchaVersionConst: {default:'v3', alternate:'v2', cloudflare:'...'}
                                        version = loginComponent.captchaVersionConst.cloudflare ||
                                                  loginComponent.captchaVersionConst.alternate ||
                                                  'Turnstile';
                                        results.push('version_from_const:' + version);
                                    }
                                    loginFormGroup.controls.captcha_version.setValue(version);
                                    loginFormGroup.controls.captcha_version.updateValueAndValidity();
                                    results.push('SET_captcha_version:' + version);
                                }

                                // Update entire form validity
                                loginFormGroup.updateValueAndValidity();
                                results.push('form_valid:' + loginFormGroup.valid);
                                results.push('form_status:' + loginFormGroup.status);
                            }

                            // Set component-level captcha properties
                            if (loginComponent) {
                                loginComponent.captchaToken = token;
                                if (loginComponent.captchaVersionConst) {
                                    loginComponent.currentCaptcha =
                                        loginComponent.captchaVersionConst.cloudflare ||
                                        loginComponent.captchaVersionConst.alternate;
                                }
                                // Ensure allowedCaptcha is set (needed for submission)
                                if (loginComponent.allowedCaptcha !== undefined) {
                                    results.push('allowedCaptcha:' + loginComponent.allowedCaptcha);
                                }
                                results.push('SET_component_captchaToken');
                            }

                            // === FALLBACK A: If form still invalid, disable captcha requirement ===
                            if (loginFormGroup && !loginFormGroup.valid && loginComponent) {
                                results.push('FORM_STILL_INVALID_trying_bypass');

                                // Clear validators on all captcha-related controls
                                for (const cn of Object.keys(loginFormGroup.controls)) {
                                    const lower = cn.toLowerCase();
                                    if (lower.includes('captcha') || lower.includes('token') ||
                                        lower.includes('turnstile') || lower.includes('otp')) {
                                        const ctrl = loginFormGroup.controls[cn];
                                        if (ctrl.clearValidators) ctrl.clearValidators();
                                        ctrl.setErrors(null);
                                        ctrl.updateValueAndValidity();
                                        results.push('cleared_validator:' + cn);
                                    }
                                }
                                loginFormGroup.updateValueAndValidity();
                                results.push('form_valid_after_clear:' + loginFormGroup.valid);
                            }

                            // === FALLBACK B: Set hidden inputs (legacy approach) ===
                            const names = ['cf-turnstile-response', 'g-recaptcha-response'];
                            for (const name of names) {
                                const input = document.querySelector('[name="' + name + '"]');
                                if (input) {
                                    const setter = Object.getOwnPropertyDescriptor(
                                        HTMLInputElement.prototype, 'value').set;
                                    setter.call(input, token);
                                    input.dispatchEvent(new Event('input', {bubbles: true}));
                                    input.dispatchEvent(new Event('change', {bubbles: true}));
                                    results.push('input_set:' + name);
                                }
                            }

                            // === FALLBACK C: Override turnstile.getResponse ===
                            if (window.turnstile) {
                                window.turnstile.getResponse = () => token;
                                results.push('getResponse_overridden');
                            }

                            return results;
                        }
                    """, token)
                    logger.info("Turnstile token injection results: %s", inject_result)
                    await page.wait_for_timeout(3000)
                except Exception as e:
                    logger.warning("CapSolver Turnstile solve failed: %s", e)
            else:
                logger.warning("No Turnstile sitekey found — button may stay disabled")

            # ── ROUTE INTERCEPTOR: Inject captcha token into login API POST ──
            # Set up BEFORE form interaction so it's ready when Angular submits.
            # From bundle analysis: VFS expects captcha_api_key + captcha_version in body.
            solved_captcha_token = token if sitekey else ""

            login_api_captured = {}

            async def intercept_login_api(route):
                """Intercept login POST and inject captcha token."""
                request = route.request
                url = request.url
                method = request.method
                post_data = request.post_data

                logger.info("[route] Intercepted %s %s", method, url[:100])

                if method == "POST" and post_data:
                    try:
                        import json as json_mod
                        body = json_mod.loads(post_data)
                        logger.info("[route] POST body keys: %s", list(body.keys()))
                        login_api_captured["url"] = url
                        login_api_captured["headers"] = dict(request.headers)
                        login_api_captured["original_body"] = body.copy()

                        modified = False
                        # Inject captcha token into existing empty fields
                        for field in list(body.keys()):
                            fl = field.lower()
                            if ("captcha" in fl or "turnstile" in fl or
                                "recaptcha" in fl or "cf_token" in fl):
                                if not body[field] or body[field] == "":
                                    body[field] = solved_captcha_token
                                    modified = True
                                    logger.info("[route] Injected token into existing field: %s", field)

                        # ADD captcha fields if they're missing entirely
                        # From bundle analysis: VFS expects captcha_api_key + captcha_version
                        if "username" in body or "password" in body:
                            # This looks like a login request
                            if "captcha_api_key" not in body:
                                body["captcha_api_key"] = solved_captcha_token
                                modified = True
                                logger.info("[route] Added captcha_api_key to login body")
                            if "captcha_version" not in body:
                                body["captcha_version"] = "Turnstile"
                                modified = True
                                logger.info("[route] Added captcha_version to login body")

                        if modified:
                            logger.info("[route] Final body keys: %s", list(body.keys()))
                            await route.continue_(post_data=json_mod.dumps(body))
                            return
                    except Exception as e:
                        logger.warning("[route] Parse error: %s", e)

                await route.continue_()

            # Intercept all requests to VFS API
            await page.route("**/lift-api.vfsglobal.com/**", intercept_login_api)
            logger.info("Route interceptor set up for login API")

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

            # Check if button is enabled — wait briefly, then force-enable
            is_disabled = await sign_in.is_disabled()
            if is_disabled:
                logger.info("Sign In button disabled — waiting 10s for callback...")
                for wait_i in range(2):  # 2 × 5s = 10s (shorter wait now)
                    await page.wait_for_timeout(5000)
                    if not await sign_in.is_disabled():
                        logger.info("Sign In button is now enabled!")
                        break
                    logger.info("Still disabled (%d/2)...", wait_i + 1)
                else:
                    logger.warning("Force-enabling Sign In button + form submission")
                    await page.evaluate("""
                        () => {
                            // Force-enable the button
                            const btn = document.querySelector('button[type="submit"]');
                            if (btn) {
                                btn.disabled = false;
                                btn.classList.remove('mat-mdc-button-disabled');
                                btn.removeAttribute('disabled');
                            }
                            // Also try to make Angular's form "valid" by removing validators
                            // Find all form controls and clear validators
                            const forms = document.querySelectorAll('form');
                            for (const f of forms) {
                                f.noValidate = true;
                            }
                        }
                    """)
                    await page.wait_for_timeout(500)
            else:
                logger.info("Sign In button is enabled!")

            await sign_in.click(force=True)
            logger.info("Clicked Sign In button")

            # Wait for navigation or API response
            logger.info("Waiting for post-login page...")
            login_success = False
            try:
                await page.wait_for_url("**/dashboard", timeout=15000)
                logger.info("Dashboard loaded — login successful!")
                login_success = True
            except Exception:
                try:
                    start_booking = page.get_by_role("button", name="Start New Booking")
                    await start_booking.wait_for(timeout=5000)
                    logger.info("Post-login page loaded (Start New Booking visible)")
                    login_success = True
                except Exception:
                    current_url = page.url
                    logger.warning("Form click did not navigate. URL: %s", current_url)

            # FALLBACK: If form submission failed, try re-patching and resubmitting
            if not login_success and solved_captcha_token:
                logger.info("Form click didn't navigate — trying deeper Angular patching...")

                # Try to find and fix the form one more time
                retry_result = await page.evaluate("""
                    (token) => {
                        const results = [];

                        // Deep walk: search ALL objects in ALL __ngContext__ arrays
                        const visited = new WeakSet();
                        function findFormGroups(obj, depth) {
                            if (!obj || depth > 5 || typeof obj !== 'object') return;
                            if (visited.has(obj)) return;
                            try { visited.add(obj); } catch(e) { return; }

                            // Check if this is a FormGroup
                            if (obj.controls && typeof obj.controls === 'object' &&
                                !Array.isArray(obj.controls)) {
                                const keys = Object.keys(obj.controls);
                                if (keys.includes('username') || keys.includes('password')) {
                                    results.push('DEEP_FOUND_FORM:' + keys.join(','));

                                    // Set captcha fields
                                    for (const cn of keys) {
                                        const lower = cn.toLowerCase();
                                        if (lower.includes('captcha') || lower.includes('token')) {
                                            obj.controls[cn].setValue(token);
                                            if (obj.controls[cn].clearValidators)
                                                obj.controls[cn].clearValidators();
                                            obj.controls[cn].setErrors(null);
                                            obj.controls[cn].updateValueAndValidity();
                                            results.push('DEEP_SET:' + cn);
                                        }
                                    }

                                    // Clear ALL validators to force form valid
                                    for (const cn of keys) {
                                        const ctrl = obj.controls[cn];
                                        if (ctrl.clearValidators) ctrl.clearValidators();
                                        ctrl.setErrors(null);
                                        ctrl.updateValueAndValidity();
                                    }
                                    obj.updateValueAndValidity();
                                    results.push('DEEP_form_valid:' + obj.valid);
                                }
                            }

                            // Recurse into object properties
                            if (Array.isArray(obj)) {
                                for (const item of obj) {
                                    findFormGroups(item, depth + 1);
                                }
                            } else {
                                for (const key of Object.keys(obj).slice(0, 50)) {
                                    try { findFormGroups(obj[key], depth + 1); }
                                    catch(e) {}
                                }
                            }
                        }

                        const allElements = document.querySelectorAll('*');
                        for (const el of allElements) {
                            if (el.__ngContext__) {
                                findFormGroups(el.__ngContext__, 0);
                            }
                        }

                        // Force-enable button again
                        const btn = document.querySelector('button[type="submit"]');
                        if (btn) {
                            btn.disabled = false;
                            btn.classList.remove('mat-mdc-button-disabled');
                            btn.removeAttribute('disabled');
                            results.push('button_force_enabled');
                        }

                        return results;
                    }
                """, solved_captcha_token)
                logger.info("Deep Angular patch result: %s", retry_result)

                # Click submit again
                await page.wait_for_timeout(1000)
                try:
                    await sign_in.click(force=True)
                    logger.info("Re-clicked Sign In button")

                    # Wait for navigation
                    try:
                        await page.wait_for_url("**/dashboard", timeout=15000)
                        logger.info("Dashboard loaded after retry!")
                        login_success = True
                    except Exception:
                        current_url = page.url
                        logger.warning("Still no navigation after retry. URL: %s", current_url)
                except Exception as e:
                    logger.warning("Re-click failed: %s", e)

            if not login_success:
                current_url = page.url
                await _log_page_debug(page, "post-login-fail")
                if "login" in current_url:
                    raise RuntimeError(f"Still on login page: {current_url}")

            # Unroute to avoid intercepting further requests
            try:
                await page.unroute("**/lift-api.vfsglobal.com/**")
            except Exception:
                pass

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
