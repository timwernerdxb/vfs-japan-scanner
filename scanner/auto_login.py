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
        # Init script: stealth patches + CAPTCHA interception
        # CRITICAL: Each section wrapped in try/catch — a single throw
        # (e.g. non-configurable navigator.connection) kills the entire script.
        await context.add_init_script("""
        () => {
            // ── STEALTH PATCHES (each wrapped to prevent cascade failure) ──
            try { Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); } catch(e) {}
            try { window.chrome = {runtime: {}, loadTimes: function(){}, csi: function(){}}; } catch(e) {}
            try {
                const oq = window.navigator.permissions.query;
                window.navigator.permissions.query = (p) =>
                    p.name === 'notifications'
                        ? Promise.resolve({state: Notification.permission})
                        : oq(p);
            } catch(e) {}
            try { Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]}); } catch(e) {}
            try { Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']}); } catch(e) {}
            try { Object.defineProperty(navigator, 'connection', {get: () => ({rtt:50,downlink:10,effectiveType:'4g',saveData:false})}); } catch(e) {}
            try { Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8}); } catch(e) {}
            try { Object.defineProperty(navigator, 'deviceMemory', {get: () => 8}); } catch(e) {}
            try { Object.defineProperty(navigator, 'platform', {get: () => 'Linux x86_64'}); } catch(e) {}
            console.log('INIT_STEALTH_DONE');

            // ── CAPTCHA: Pre-built fake Turnstile that Angular finds immediately ──
            // KEY INSIGHT: In headless, real api.js never sets window.turnstile
            // (CF challenge fails — no WebGL, /pat/ returns 401). Angular checks
            // for window.turnstile during bootstrap, finds undefined, and skips.
            // FIX: The getter returns a pre-built fake when _realTs is undefined.
            // Angular finds the fake, calls render(), we capture the callback.
            // CapSolver token arrives later → we invoke the captured callback.
            try {
                window.__captchaToken = null;
                window.__turnstileCallback = null;
                window.__allTurnstileCallbacks = [];
                window.__capturedTurnstileSitekey = null;
                window.__tsWrapped = false;

                console.log('INIT_HOST:' + window.location.hostname);

                // Pre-built fake turnstile that captures Angular's callback
                var _fakeTs = {
                    render: function(container, options) {
                        console.log('FAKE_TS_RENDER container=' +
                            (typeof container === 'string' ? container : 'element'));
                        if (options) {
                            if (options.sitekey) {
                                window.__capturedTurnstileSitekey = options.sitekey;
                                console.log('FAKE_TS_SITEKEY:' + options.sitekey);
                            }
                            if (typeof options.callback === 'function') {
                                window.__turnstileCallback = options.callback;
                                window.__allTurnstileCallbacks.push(options.callback);
                                console.log('FAKE_TS_CB_CAPTURED total=' +
                                    window.__allTurnstileCallbacks.length);
                                // If token already solved (race condition), invoke now
                                if (window.__captchaToken) {
                                    try {
                                        options.callback(window.__captchaToken);
                                        console.log('FAKE_TS_CB_INVOKED_IMMEDIATE');
                                    } catch(e) { console.log('FAKE_TS_CB_ERR:'+e.message); }
                                }
                            }
                            // Suppress error callback — our fake never errors
                            if (options['error-callback']) {
                                options['error-callback'] = function() {
                                    console.log('FAKE_TS_ERROR_SUPPRESSED');
                                };
                            }
                            // Suppress expired callback
                            if (options['expired-callback']) {
                                options['expired-callback'] = function() {
                                    console.log('FAKE_TS_EXPIRED_SUPPRESSED');
                                };
                            }
                        }
                        return 'fake_widget_0';
                    },
                    execute: function(container, options) {
                        console.log('FAKE_TS_EXECUTE');
                        if (options && typeof options.callback === 'function') {
                            window.__turnstileCallback = options.callback;
                            window.__allTurnstileCallbacks.push(options.callback);
                            console.log('FAKE_TS_EXEC_CB_CAPTURED');
                            if (window.__captchaToken) {
                                options.callback(window.__captchaToken);
                            }
                        }
                        return window.__captchaToken || '';
                    },
                    getResponse: function() {
                        return window.__captchaToken || '';
                    },
                    reset: function() { console.log('FAKE_TS_RESET'); },
                    remove: function() {},
                    isExpired: function() { return false; },
                    ready: function(cb) {
                        console.log('FAKE_TS_READY');
                        if (typeof cb === 'function') cb();
                    },
                    __wrapped: true
                };

                // Wrapper for real turnstile (if it ever arrives)
                function _wrapTurnstile(ts) {
                    if (!ts || typeof ts !== 'object' || ts.__wrapped) return;
                    if (typeof ts.render === 'function') {
                        var origRender = ts.render.bind(ts);
                        ts.render = function(container, options) {
                            console.log('TS_REAL_RENDER_INTERCEPTED');
                            if (options) {
                                if (options.sitekey) {
                                    window.__capturedTurnstileSitekey = options.sitekey;
                                }
                                if (typeof options.callback === 'function') {
                                    window.__turnstileCallback = options.callback;
                                    window.__allTurnstileCallbacks.push(options.callback);
                                    console.log('TS_REAL_CB_CAPTURED');
                                    if (window.__captchaToken) {
                                        try {
                                            options.callback(window.__captchaToken);
                                            console.log('TS_REAL_CB_INVOKED');
                                        } catch(e) {}
                                    }
                                }
                                if (options['error-callback']) {
                                    options['error-callback'] = function() {
                                        console.log('TS_REAL_ERROR_SUPPRESSED');
                                    };
                                }
                            }
                            try { return origRender(container, options); }
                            catch(e) { return 'w0'; }
                        };
                    }
                    ts.__wrapped = true;
                    window.__tsWrapped = true;
                    console.log('TS_REAL_WRAPPED_OK');
                }

                // Getter/setter trap:
                // - getter returns real turnstile if set, otherwise returns fake
                // - setter wraps real turnstile when api.js sets it
                var _realTs = undefined;
                try {
                    Object.defineProperty(window, 'turnstile', {
                        get: function() { return _realTs || _fakeTs; },
                        set: function(v) {
                            console.log('TS_SET type=' + typeof v);
                            _realTs = v;
                            if (v && typeof v === 'object') _wrapTurnstile(v);
                        },
                        configurable: true,
                        enumerable: true
                    });
                    console.log('INIT_TS_TRAP_OK (fake ready)');
                } catch(e) { console.log('INIT_TS_TRAP_FAIL:'+e.message); }

                console.log('INIT_CAPTCHA_OK ts_type=' + typeof window.turnstile);
            } catch(e) { console.log('INIT_CAPTCHA_FAIL:'+e.message); }

            // ── SCRIPT LOAD INTERCEPTION ──
            // Angular waits for <script id="volt-recaptcha"> 'load' event before
            // calling turnstile.render(). But the script loads BEFORE Angular
            // bootstraps → 'load' already fired → Angular's listener never fires
            // → render() never called → callback never captured.
            // FIX: Track script loads. When a 'load' listener is added to an
            // already-loaded script, fire the handler immediately.
            try {
                var _loadedScripts = new WeakSet();

                // Track ALL script load events via capture phase
                // (capture phase catches non-bubbling 'load' events on descendants)
                document.addEventListener('load', function(e) {
                    if (e.target && e.target.tagName === 'SCRIPT') {
                        _loadedScripts.add(e.target);
                        console.log('SCRIPT_LOADED:' + (e.target.id || 'anon') +
                                     ' src=' + (e.target.src || '').substring(0, 80));
                    }
                }, true);

                // Override addEventListener: fire 'load' immediately for already-loaded scripts
                var _origAEL = EventTarget.prototype.addEventListener;
                EventTarget.prototype.addEventListener = function(type, fn, opts) {
                    _origAEL.call(this, type, fn, opts);
                    if (type === 'load' && this instanceof HTMLScriptElement &&
                        _loadedScripts.has(this)) {
                        var el = this;
                        console.log('LATE_LOAD_LISTENER:' + (el.id || 'anon') +
                                    ' src=' + (el.src || '').substring(0, 60));
                        setTimeout(function() {
                            try {
                                fn.call(el, new Event('load'));
                                console.log('LATE_LOAD_FIRED:' + (el.id || 'anon'));
                            } catch(e) {
                                console.log('LATE_LOAD_ERR:' + e.message);
                            }
                        }, 0);
                    }
                };

                // MutationObserver for logging script additions
                var _obs = new MutationObserver(function(mutations) {
                    for (var mi = 0; mi < mutations.length; mi++) {
                        var added = mutations[mi].addedNodes;
                        for (var ni = 0; ni < added.length; ni++) {
                            var node = added[ni];
                            if (node.tagName === 'SCRIPT' && node.src) {
                                if (node.src.indexOf('challenges.cloudflare.com') >= 0 ||
                                    node.id === 'volt-recaptcha') {
                                    console.log('SCRIPT_ADDED:' + (node.id || 'anon') +
                                                ' src=' + node.src.substring(0, 120));
                                }
                            }
                        }
                    }
                });
                _obs.observe(document.documentElement, {childList: true, subtree: true});

                // Periodic fallback: dispatch 'load' on volt-recaptcha every 5s
                // until callback is captured (handles edge cases where the capture-
                // phase tracking missed the load event)
                var _renderRetry = setInterval(function() {
                    if (window.__turnstileCallback) {
                        clearInterval(_renderRetry);
                        console.log('RENDER_RETRY_DONE: callback captured');
                        return;
                    }
                    var volt = document.getElementById('volt-recaptcha');
                    if (volt) {
                        _loadedScripts.add(volt); // ensure it's tracked
                        volt.dispatchEvent(new Event('load'));
                        console.log('RENDER_RETRY: dispatched load on volt-recaptcha');
                    }
                }, 5000);
                setTimeout(function() { clearInterval(_renderRetry); }, 120000);

                console.log('INIT_SCRIPT_INTERCEPT_OK');
            } catch(e) { console.log('INIT_SCRIPT_INTERCEPT_FAIL:' + e.message); }
        }
        """)

        # Intercept requests to capture auth headers and CAPTCHA sitekeys
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

        # Capture JS console messages (errors + fake Turnstile events)
        js_errors = []

        def on_console(msg):
            text = msg.text
            if msg.type in ("error", "warning"):
                logger.info("[console.%s] %s", msg.type, text)
                js_errors.append(text)
            # Log init script section confirmations
            if text.startswith("INIT_"):
                logger.info("[console] %s", text)
            # Log Turnstile wrapper events (from init script wrapper)
            if text.startswith("TS_"):
                logger.info("[console] %s", text)
            # Log fake Turnstile events (from route-injected script)
            if text.startswith("FAKE_TS_"):
                logger.info("[console] %s", text)
            # Log script additions (from MutationObserver)
            if text.startswith("SCRIPT_ADDED:"):
                logger.info("[console] %s", text)
            # Log script load interception events
            if text.startswith("SCRIPT_LOADED:") or text.startswith("LATE_LOAD_"):
                logger.info("[console] %s", text)
            if text.startswith("RENDER_RETRY"):
                logger.info("[console] %s", text)
            # Capture sitekey from Turnstile wrapper or fake render
            if "TS_SITEKEY:" in text:
                key = text.split("TS_SITEKEY:")[1].strip()
                if not captured_turnstile_sitekey.get("key"):
                    captured_turnstile_sitekey["key"] = key
                    logger.info("Captured Turnstile sitekey from wrapper: %s", key)
            if "FAKE_TS_SITEKEY:" in text:
                key = text.split("FAKE_TS_SITEKEY:")[1].strip()
                if not captured_turnstile_sitekey.get("key"):
                    captured_turnstile_sitekey["key"] = key
                    logger.info("Captured Turnstile sitekey from fake render: %s", key)

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
                    # ── DIAGNOSTIC: Understand Angular state before injection ──
                    diag = await page.evaluate("""
                        () => {
                            const r = {};

                            // Angular globals
                            r.ng_exists = typeof ng !== 'undefined';
                            r.ng_getComponent = typeof ng !== 'undefined' && typeof ng.getComponent === 'function';
                            r.getAllRoots = typeof getAllAngularRootElements === 'function';
                            r.Zone = typeof Zone !== 'undefined';

                            // Check __ngContext__ on elements
                            r.ngCtx = [];
                            const all = document.querySelectorAll('*');
                            for (const el of all) {
                                if (el.__ngContext__ !== undefined && el.__ngContext__ !== null) {
                                    r.ngCtx.push({
                                        tag: el.tagName.toLowerCase(),
                                        id: (el.id || '').substring(0, 20),
                                        type: typeof el.__ngContext__,
                                        isArr: Array.isArray(el.__ngContext__),
                                        val: typeof el.__ngContext__ === 'number' ? el.__ngContext__ : null,
                                        len: Array.isArray(el.__ngContext__) ? el.__ngContext__.length : null,
                                    });
                                }
                                if (r.ngCtx.length >= 10) break;
                            }

                            // formcontrolname elements (critical for form patching)
                            r.formControls = [];
                            const fcn = document.querySelectorAll('[formcontrolname]');
                            for (const el of fcn) {
                                r.formControls.push({
                                    tag: el.tagName.toLowerCase(),
                                    fcn: el.getAttribute('formcontrolname'),
                                    type: el.type || '',
                                    val: (el.value || '').substring(0, 20),
                                });
                            }

                            // Buttons
                            r.buttons = [];
                            const btns = document.querySelectorAll('button');
                            for (const b of btns) {
                                const txt = (b.textContent || '').trim().substring(0, 30);
                                if (txt) {
                                    r.buttons.push({
                                        type: b.type, text: txt, disabled: b.disabled,
                                    });
                                }
                            }

                            // reCAPTCHA / Turnstile state
                            r.grecaptcha = typeof grecaptcha !== 'undefined';
                            r.turnstile_type = typeof window.turnstile;
                            r.turnstile_wrapped = !!(window.turnstile && window.turnstile.__wrapped);
                            r.callback_captured = !!window.__turnstileCallback;
                            r.recaptchaEls = document.querySelectorAll('.g-recaptcha, [data-sitekey]').length;
                            r.turnstileEls = document.querySelectorAll('.cf-turnstile, [data-turnstile-sitekey]').length;

                            // Check Symbol properties on elements (Angular might use Symbols)
                            r.symbolProps = [];
                            try {
                                const formEl = document.querySelector('form');
                                if (formEl) {
                                    const syms = Object.getOwnPropertySymbols(formEl);
                                    r.symbolProps = syms.map(s => s.toString()).slice(0, 5);
                                }
                            } catch(e) {}

                            return r;
                        }
                    """)
                    logger.info("Angular diagnostic: %s", diag)

                    logger.info("Requesting CapSolver to solve Turnstile...")
                    token = solve_turnstile(VFS_LOGIN_URL, sitekey)
                    logger.info("Turnstile solved! Token length: %d", len(token))

                    # ── SET TOKEN + INVOKE CAPTURED CALLBACK ──
                    # The init script's fake turnstile is always present via the
                    # getter (returns _fakeTs when _realTs is undefined). Angular
                    # should have already found it and called render() during
                    # bootstrap, capturing the callback in __turnstileCallback.
                    # Now we set the token and invoke the callback.
                    inject_result = await page.evaluate("""
                        (token) => {
                            const r = {};
                            window.__captchaToken = token;
                            r.token_set = true;

                            // Check state
                            r.ts_type = typeof window.turnstile;
                            r.ts_wrapped = !!(window.turnstile && window.turnstile.__wrapped);
                            r.cb_captured = !!window.__turnstileCallback;
                            r.all_cbs = (window.__allTurnstileCallbacks || []).length;
                            r.sitekey = window.__capturedTurnstileSitekey || null;

                            // Invoke ALL captured callbacks with token
                            var cbs = window.__allTurnstileCallbacks || [];
                            r.cbs_invoked = 0;
                            for (var i = 0; i < cbs.length; i++) {
                                try {
                                    cbs[i](token);
                                    r.cbs_invoked++;
                                    console.log('TS_CB_INVOKED idx=' + i);
                                } catch(e) {
                                    console.log('TS_CB_INVOKE_ERR idx=' + i + ': ' + e.message);
                                }
                            }

                            // Check button state after invoking callbacks
                            var btns = document.querySelectorAll('button');
                            for (var b of btns) {
                                if ((b.textContent || '').includes('Sign In')) {
                                    r.btn_disabled = b.disabled;
                                    break;
                                }
                            }

                            return r;
                        }
                    """, token)
                    logger.info("Token inject result: %s", inject_result)

                    # If no callback was captured, Angular may not have called
                    # render() yet. Try dispatching 'load' on volt-recaptcha
                    # to trigger Angular's onload handler.
                    if not inject_result.get("cb_captured"):
                        logger.info("No callback captured — dispatching load event...")
                        trigger_result = await page.evaluate("""
                            () => {
                                const r = {};
                                var volt = document.querySelector(
                                    '#volt-recaptcha, script[src*="turnstile"]');
                                if (volt) {
                                    r.volt = volt.id + ' src=' + (volt.src||'').substring(0,80);
                                    volt.dispatchEvent(new Event('load'));
                                    r.load_dispatched = true;
                                } else {
                                    r.volt = 'not_found';
                                }
                                return r;
                            }
                        """)
                        logger.info("Load trigger: %s", trigger_result)
                        await page.wait_for_timeout(3000)

                        # Check if callback appeared after load dispatch
                        cb_after = await page.evaluate("""
                            (token) => {
                                var r = {
                                    cb: !!window.__turnstileCallback,
                                    cbs: (window.__allTurnstileCallbacks || []).length,
                                };
                                // Invoke if captured
                                if (window.__turnstileCallback) {
                                    try {
                                        window.__turnstileCallback(token);
                                        r.invoked = true;
                                        console.log('TS_CB_INVOKED_AFTER_LOAD');
                                    } catch(e) { r.err = e.message; }
                                }
                                return r;
                            }
                        """, token)
                        logger.info("After load trigger: %s", cb_after)

                        # Poll for callback (script load interception is async)
                        if not cb_after.get("cb"):
                            logger.info("Polling for callback capture (up to 10s)...")
                            for poll_i in range(10):
                                await page.wait_for_timeout(1000)
                                cb_poll = await page.evaluate("""
                                    () => ({
                                        cb: !!window.__turnstileCallback,
                                        cbs: (window.__allTurnstileCallbacks || []).length,
                                    })
                                """)
                                if cb_poll.get("cb"):
                                    logger.info("Callback captured after %ds polling!", poll_i + 1)
                                    await page.evaluate("""
                                        (token) => {
                                            var cbs = window.__allTurnstileCallbacks || [];
                                            for (var i = 0; i < cbs.length; i++) {
                                                try { cbs[i](token); } catch(e) {}
                                            }
                                            console.log('TS_CB_INVOKED_AFTER_POLL cbs=' + cbs.length);
                                        }
                                    """, token)
                                    break
                                if (poll_i + 1) % 3 == 0:
                                    logger.info("Poll %d/10 — still no callback", poll_i + 1)

                        # FALLBACK: Directly patch Angular FormGroup
                        # If callback STILL not captured, find Angular's reactive
                        # form and set captcha_api_key directly.
                        final_cb = await page.evaluate("() => !!window.__turnstileCallback")
                        if not final_cb:
                            logger.info("Callback never captured — trying Angular FormGroup fallback...")
                            fg_result = await page.evaluate("""
                                (token) => {
                                    var r = {};

                                    // Check volt-recaptcha element
                                    var voltEl = document.querySelector('volt-recaptcha');
                                    r.volt_exists = !!voltEl;
                                    if (voltEl) {
                                        r.volt_tag = voltEl.tagName;
                                        r.volt_ctx_type = typeof voltEl.__ngContext__;
                                        r.volt_ctx_isArr = Array.isArray(voltEl.__ngContext__);
                                    }

                                    // Search ALL elements for Angular LView containing FormGroup
                                    var allEls = document.querySelectorAll('*');
                                    for (var i = 0; i < allEls.length; i++) {
                                        var el = allEls[i];
                                        var ctx = el.__ngContext__;
                                        if (!Array.isArray(ctx)) continue;

                                        // Walk LView slots looking for FormGroup with captcha_api_key
                                        for (var j = 0; j < ctx.length && j < 300; j++) {
                                            try {
                                                var item = ctx[j];
                                                if (!item || typeof item !== 'object') continue;
                                                if (!item.controls) continue;
                                                if (!item.controls.captcha_api_key) continue;

                                                r.fg_found = true;
                                                r.fg_host = el.tagName;
                                                r.fg_idx = j;
                                                r.fg_controls = Object.keys(item.controls);
                                                r.fg_status_before = item.status;

                                                // Set captcha values
                                                item.controls.captcha_api_key.setValue(token);
                                                if (item.controls.captcha_version) {
                                                    item.controls.captcha_version.setValue('Turnstile');
                                                }
                                                item.updateValueAndValidity();
                                                r.fg_status_after = item.status;
                                                r.fg_valid = item.valid;
                                                console.log('FG_PATCHED status=' + item.status);
                                                break;
                                            } catch(e) { /* skip */ }
                                        }
                                        if (r.fg_found) break;
                                    }

                                    // Check button state
                                    var btns = document.querySelectorAll('button');
                                    for (var b of btns) {
                                        if ((b.textContent || '').indexOf('Sign In') >= 0) {
                                            r.btn_disabled = b.disabled;
                                            break;
                                        }
                                    }

                                    return r;
                                }
                            """, token)
                            logger.info("Angular FormGroup fallback: %s", fg_result)

                    # Brief wait then check button state
                    await page.wait_for_timeout(2000)
                    pre_click = await page.evaluate("""
                        () => ({
                            cb: !!window.__turnstileCallback,
                            cbs: (window.__allTurnstileCallbacks || []).length,
                            ts_type: typeof window.turnstile,
                            token: !!window.__captchaToken,
                            btn_disabled: (() => {
                                var btns = document.querySelectorAll('button');
                                for (var b of btns) {
                                    if ((b.textContent || '').includes('Sign In')) return b.disabled;
                                }
                                return null;
                            })(),
                        })
                    """)
                    logger.info("Pre-click state: %s", pre_click)

                except Exception as e:
                    logger.warning("CapSolver Turnstile solve failed: %s", e)
            else:
                logger.warning("No Turnstile sitekey found — will rely on hardcoded sitekey")

            # Determine best captcha token for route interceptor
            solved_captcha_token = token if sitekey else ""
            captcha_version = "Turnstile"

            # ── ROUTE INTERCEPTOR: Inject captcha token into login API POST ──
            # Belt-and-suspenders: even if fake Turnstile callback works,
            # ensure the POST body has captcha_api_key + captcha_version.

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
                                body["captcha_version"] = captcha_version
                                modified = True
                                logger.info("[route] Added captcha_version=%s to login body", captcha_version)

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
            # NOTE: VFS button does NOT have type="submit" — use text match first
            logger.info("Looking for Sign In button...")
            sign_in = page.locator('button:has-text("Sign In")')
            try:
                await sign_in.wait_for(state="attached", timeout=10000)
                logger.info("Sign In button found")
            except Exception:
                # Fallback to type="submit"
                sign_in = page.locator('button[type="submit"]')
                try:
                    await sign_in.wait_for(state="attached", timeout=10000)
                    logger.info("Sign In button found via type=submit")
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
                            // Force-enable ALL buttons containing "Sign In"
                            const allBtns = document.querySelectorAll('button');
                            for (const btn of allBtns) {
                                if ((btn.textContent || '').includes('Sign In')) {
                                    btn.disabled = false;
                                    btn.classList.remove('mat-mdc-button-disabled');
                                    btn.removeAttribute('disabled');
                                }
                            }
                            // Also try type=submit as fallback
                            const submitBtn = document.querySelector('button[type="submit"]');
                            if (submitBtn) {
                                submitBtn.disabled = false;
                                submitBtn.classList.remove('mat-mdc-button-disabled');
                                submitBtn.removeAttribute('disabled');
                            }
                            // Set forms to noValidate
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

            # ── POST-CLICK: Wait for navigation ──
            # After clicking Sign In, Angular may call turnstile.render() which
            # our init script wrapper intercepts to capture the callback.
            # If callback is captured post-click, we invoke it with our token.
            # The route interceptor ensures captcha fields are in the login POST.
            logger.info("Waiting for post-login navigation...")
            login_success = False

            for nav_wait in range(60):  # 60 × 2s = 120s max
                current_url = page.url

                # Check for successful navigation
                if "dashboard" in current_url or "application-detail" in current_url:
                    logger.info("Navigation detected — URL: %s", current_url)
                    login_success = True
                    break

                try:
                    start_booking = page.locator('button:has-text("Start New Booking")')
                    if await start_booking.count() > 0:
                        logger.info("Post-login page loaded (Start New Booking visible)")
                        login_success = True
                        break
                except Exception:
                    pass

                # Log state periodically + invoke any newly captured callbacks
                if (nav_wait + 1) % 5 == 0:
                    state = await page.evaluate("""
                        (token) => {
                            var r = {
                                cb: !!window.__turnstileCallback,
                                cbs: (window.__allTurnstileCallbacks || []).length,
                                ts: typeof window.turnstile,
                                wrapped: !!(window.turnstile && window.turnstile.__wrapped),
                                token: !!window.__captchaToken,
                            };
                            // If callback appeared since last check, invoke it
                            if (window.__turnstileCallback && token) {
                                try {
                                    window.__turnstileCallback(token);
                                    r.cb_invoked = true;
                                    console.log('TS_CB_INVOKED_IN_WAIT_LOOP');
                                } catch(e) { r.cb_err = e.message; }
                            }
                            return r;
                        }
                    """, token if token else "")
                    logger.info("Wait %d/60 — URL: %s | state: %s",
                                nav_wait + 1, current_url, state)

                # At 30s mark, force-enable + re-click as fallback
                if nav_wait == 15:
                    logger.info("30s elapsed — force-enable + re-click fallback")
                    await page.evaluate("""
                        () => {
                            const allBtns = document.querySelectorAll('button');
                            for (const btn of allBtns) {
                                if ((btn.textContent || '').includes('Sign In')) {
                                    btn.disabled = false;
                                    btn.classList.remove('mat-mdc-button-disabled');
                                    btn.removeAttribute('disabled');
                                }
                            }
                            const forms = document.querySelectorAll('form');
                            for (const f of forms) f.noValidate = true;
                        }
                    """)
                    await page.wait_for_timeout(500)
                    try:
                        await sign_in.click(force=True)
                        logger.info("Re-clicked Sign In button")
                    except Exception as e:
                        logger.warning("Re-click failed: %s", e)

                    # Re-invoke callback in case Angular needs it again
                    if token:
                        await page.evaluate("""
                            (token) => {
                                if (window.__turnstileCallback) {
                                    try { window.__turnstileCallback(token); console.log('RECLICK_CB_INVOKED'); }
                                    catch(e) {}
                                }
                            }
                        """, token)

                await page.wait_for_timeout(2000)

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
