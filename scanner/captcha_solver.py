"""
CapSolver CAPTCHA solver (Turnstile + reCAPTCHA v3).

Uses the CapSolver API to solve Cloudflare Turnstile and Google reCAPTCHA v3.
Get an API key at: https://www.capsolver.com/
"""

import json
import logging
import os
import time
from urllib.request import Request, urlopen
from urllib.error import URLError

CAPSOLVER_CREATE_URL = "https://api.capsolver.com/createTask"
CAPSOLVER_RESULT_URL = "https://api.capsolver.com/getTaskResult"

logger = logging.getLogger("captcha_solver")


def _get_api_key() -> str:
    """Read API key at call time (not import time) to handle late env var loading."""
    key = (os.environ.get("CAPSOLVER_API_KEY", "")
           or os.environ.get("CAP_SOLVER_API_KEY", "")).strip()
    if key:
        logger.info("CapSolver API key loaded (length: %d, starts: %s...)", len(key), key[:8])
    else:
        # Log ALL env vars that contain "CAP" or "SOLVER" to help debug
        cap_vars = {k: v[:8] + "..." for k, v in os.environ.items()
                    if "CAP" in k.upper() or "SOLVER" in k.upper()}
        logger.warning("CAPSOLVER_API_KEY not found. Related env vars: %s", cap_vars or "none")
    return key


def _proxy_task_fields(proxy: dict | None) -> dict:
    """Turn a proxy dict into the four fields CapSolver's proxied tasks want.

    Accepts either the shape used elsewhere in this repo
    ({"server": "host:port", "username": "...", "password": "..."}) or
    a direct dict with proxyType/proxyAddress/... already set.
    """
    if not proxy:
        return {}
    if "proxyAddress" in proxy:
        return proxy
    server = str(proxy.get("server", "")).strip()
    if not server:
        return {}
    # Strip scheme if present
    if "://" in server:
        scheme, rest = server.split("://", 1)
    else:
        scheme, rest = "http", server
    if ":" in rest:
        host, port_s = rest.rsplit(":", 1)
    else:
        host, port_s = rest, "80"
    try:
        port = int(port_s)
    except ValueError:
        port = 80
    fields = {
        "proxyType": scheme,
        "proxyAddress": host,
        "proxyPort": port,
    }
    if proxy.get("username"):
        fields["proxyLogin"] = proxy["username"]
    if proxy.get("password"):
        fields["proxyPassword"] = proxy["password"]
    return fields


def solve_turnstile(
    website_url: str, website_key: str, timeout: int = 120,
    proxy: dict | None = None,
) -> str:
    """
    Solve a Cloudflare Turnstile challenge via CapSolver API.

    Args:
        website_url: The URL of the page with the Turnstile widget.
        website_key: The Turnstile sitekey (usually starts with 0x4...).
        timeout: Max seconds to wait for solution.
        proxy: Optional proxy dict. When provided, CapSolver uses the
            proxied task variant (`AntiTurnstileTask`) so the token is
            bound to *that* egress IP — required when the solved token
            will be submitted from a different network than CapSolver's
            own pool (which triggers Cloudflare 600010 "challenge
            failed"). Shape: {"server": "host:port", "username": "..",
            "password": ".."}.

    Returns:
        The solved Turnstile token string.

    Raises:
        RuntimeError: If solving fails or times out.
    """
    api_key = _get_api_key()
    if not api_key:
        raise RuntimeError("CAPSOLVER_API_KEY environment variable not set")

    proxy_fields = _proxy_task_fields(proxy)
    if proxy_fields:
        task_type = "AntiTurnstileTask"
        logger.info(
            "Solving Turnstile for %s (sitekey=%s...) via proxy %s:%s",
            website_url, website_key[:12],
            proxy_fields.get("proxyAddress"), proxy_fields.get("proxyPort"),
        )
    else:
        task_type = "AntiTurnstileTaskProxyLess"
        logger.info(
            "Solving Turnstile for %s (sitekey=%s...) — proxyless "
            "(token will be IP-bound to CapSolver's pool!)",
            website_url, website_key[:12],
        )

    # Step 1: Create task
    task = {
        "type": task_type,
        "websiteURL": website_url,
        "websiteKey": website_key,
    }
    task.update(proxy_fields)
    payload = json.dumps({
        "clientKey": api_key,
        "task": task,
    }).encode("utf-8")

    req = Request(CAPSOLVER_CREATE_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urlopen(req, timeout=30)
        data = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"CapSolver createTask failed: {e}")

    if data.get("errorId") and data.get("errorId") != 0:
        raise RuntimeError(f"CapSolver error: {data.get('errorDescription', data)}")

    task_id = data.get("taskId")
    if not task_id:
        raise RuntimeError(f"CapSolver returned no taskId: {data}")

    logger.info("Task created: %s — polling for result...", task_id)

    # Step 2: Poll for result
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(3)

        poll_payload = json.dumps({
            "clientKey": api_key,
            "taskId": task_id,
        }).encode("utf-8")

        poll_req = Request(CAPSOLVER_RESULT_URL, data=poll_payload, method="POST")
        poll_req.add_header("Content-Type", "application/json")

        try:
            poll_resp = urlopen(poll_req, timeout=30)
            result = json.loads(poll_resp.read().decode("utf-8"))
        except (URLError, json.JSONDecodeError) as e:
            logger.warning("Poll error: %s — retrying...", e)
            continue

        status = result.get("status", "")

        if status == "ready":
            token = result.get("solution", {}).get("token", "")
            if token:
                elapsed = int(time.time() - start)
                logger.info("Turnstile solved in %ds (token length: %d)", elapsed, len(token))
                return token
            raise RuntimeError(f"CapSolver returned ready but no token: {result}")

        if status == "failed":
            raise RuntimeError(f"CapSolver task failed: {result.get('errorDescription', result)}")

        # Still processing
        logger.debug("Task status: %s — waiting...", status)

    raise RuntimeError(f"CapSolver timeout after {timeout}s")


def solve_hcaptcha(
    website_url: str, website_key: str, timeout: int = 180,
    invisible: bool = False, is_enterprise: bool = False,
    enterprise_payload: dict | None = None, user_agent: str | None = None,
    proxy: dict | None = None,
) -> str:
    """
    Solve an hCaptcha challenge via CapSolver API.

    Args:
        website_url: The URL of the page with the hCaptcha widget.
        website_key: The hCaptcha sitekey (usually a UUID).
        timeout: Max seconds to wait for a solution. hCaptcha challenges
                 can take 60-150s to solve, so timeout defaults higher
                 than Turnstile.
        invisible: True if this is an invisible hCaptcha (no visible widget).
        is_enterprise: True for hCaptcha Enterprise.
        enterprise_payload: Optional dict with enterprise-specific params
                            (rqdata, sentry, apiEndpoint, etc.).
        user_agent: Optional UA string; helps CapSolver match browser fingerprint.

    Returns:
        The solved hCaptcha response token (goes into the
        `h-captcha-response` hidden input / `hcaptcha` callback).

    Raises:
        RuntimeError: If solving fails or times out.
    """
    api_key = _get_api_key()
    if not api_key:
        raise RuntimeError("CAPSOLVER_API_KEY environment variable not set")

    logger.info(
        "Solving hCaptcha for %s (sitekey=%s..., invisible=%s, enterprise=%s)",
        website_url, website_key[:12], invisible, is_enterprise,
    )

    proxy_fields = _proxy_task_fields(proxy)
    proxied = bool(proxy_fields)
    if is_enterprise:
        task_type = "HCaptchaEnterpriseTask" if proxied else "HCaptchaEnterpriseTaskProxyLess"
    else:
        task_type = "HCaptchaTask" if proxied else "HCaptchaTaskProxyLess"
    if proxied:
        logger.info(
            "hCaptcha will be solved via proxy %s:%s (IP-bound token)",
            proxy_fields.get("proxyAddress"), proxy_fields.get("proxyPort"),
        )

    task: dict = {
        "type": task_type,
        "websiteURL": website_url,
        "websiteKey": website_key,
        "isInvisible": invisible,
    }
    task.update(proxy_fields)
    if enterprise_payload:
        task["enterprisePayload"] = enterprise_payload
    if user_agent:
        task["userAgent"] = user_agent

    payload = json.dumps({"clientKey": api_key, "task": task}).encode("utf-8")

    req = Request(CAPSOLVER_CREATE_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urlopen(req, timeout=30)
        data = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"CapSolver createTask failed: {e}")

    if data.get("errorId") and data.get("errorId") != 0:
        raise RuntimeError(f"CapSolver error: {data.get('errorDescription', data)}")

    task_id = data.get("taskId")
    if not task_id:
        raise RuntimeError(f"CapSolver returned no taskId: {data}")

    logger.info("hCaptcha task created: %s — polling for result...", task_id)

    start = time.time()
    while time.time() - start < timeout:
        time.sleep(5)  # hCaptcha polling: longer than Turnstile

        poll_payload = json.dumps({
            "clientKey": api_key, "taskId": task_id,
        }).encode("utf-8")

        poll_req = Request(CAPSOLVER_RESULT_URL, data=poll_payload, method="POST")
        poll_req.add_header("Content-Type", "application/json")

        try:
            poll_resp = urlopen(poll_req, timeout=30)
            result = json.loads(poll_resp.read().decode("utf-8"))
        except (URLError, json.JSONDecodeError) as e:
            logger.warning("hCaptcha poll error: %s — retrying...", e)
            continue

        status = result.get("status", "")

        if status == "ready":
            sol = result.get("solution", {}) or {}
            # CapSolver returns hCaptcha token under different keys depending
            # on task type / enterprise; check the common ones.
            token = (
                sol.get("gRecaptchaResponse")
                or sol.get("token")
                or sol.get("hCaptchaResponse")
                or sol.get("captchaResponse")
                or ""
            )
            if token:
                elapsed = int(time.time() - start)
                logger.info(
                    "hCaptcha solved in %ds (token length: %d)", elapsed, len(token),
                )
                return token
            raise RuntimeError(
                f"CapSolver returned ready but no hCaptcha token in solution: {result}"
            )

        if status == "failed":
            raise RuntimeError(
                f"CapSolver hCaptcha task failed: {result.get('errorDescription', result)}"
            )

        logger.debug("hCaptcha task status: %s — waiting...", status)

    raise RuntimeError(f"CapSolver hCaptcha timeout after {timeout}s")


def solve_recaptcha_v3(
    website_url: str, website_key: str, page_action: str = "login", timeout: int = 120
) -> str:
    """
    Solve a Google reCAPTCHA v3 challenge via CapSolver API.

    Args:
        website_url: The URL of the page with the reCAPTCHA.
        website_key: The reCAPTCHA v3 sitekey (usually starts with 6L...).
        page_action: The action parameter (e.g., 'login').
        timeout: Max seconds to wait for solution.

    Returns:
        The solved reCAPTCHA v3 token string.

    Raises:
        RuntimeError: If solving fails or times out.
    """
    api_key = _get_api_key()
    if not api_key:
        raise RuntimeError("CAPSOLVER_API_KEY environment variable not set")

    logger.info(
        "Solving reCAPTCHA v3 for %s (sitekey=%s..., action=%s)",
        website_url, website_key[:12], page_action,
    )

    payload = json.dumps({
        "clientKey": api_key,
        "task": {
            "type": "ReCaptchaV3TaskProxyLess",
            "websiteURL": website_url,
            "websiteKey": website_key,
            "pageAction": page_action,
        },
    }).encode("utf-8")

    req = Request(CAPSOLVER_CREATE_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urlopen(req, timeout=30)
        data = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"CapSolver createTask failed: {e}")

    if data.get("errorId") and data.get("errorId") != 0:
        raise RuntimeError(f"CapSolver error: {data.get('errorDescription', data)}")

    task_id = data.get("taskId")
    if not task_id:
        raise RuntimeError(f"CapSolver returned no taskId: {data}")

    logger.info("Task created: %s — polling for result...", task_id)

    start = time.time()
    while time.time() - start < timeout:
        time.sleep(3)

        poll_payload = json.dumps({
            "clientKey": api_key,
            "taskId": task_id,
        }).encode("utf-8")

        poll_req = Request(CAPSOLVER_RESULT_URL, data=poll_payload, method="POST")
        poll_req.add_header("Content-Type", "application/json")

        try:
            poll_resp = urlopen(poll_req, timeout=30)
            result = json.loads(poll_resp.read().decode("utf-8"))
        except (URLError, json.JSONDecodeError) as e:
            logger.warning("Poll error: %s — retrying...", e)
            continue

        status = result.get("status", "")

        if status == "ready":
            token = result.get("solution", {}).get("gRecaptchaResponse", "")
            if token:
                elapsed = int(time.time() - start)
                logger.info("reCAPTCHA v3 solved in %ds (token length: %d)", elapsed, len(token))
                return token
            raise RuntimeError(f"CapSolver returned ready but no token: {result}")

        if status == "failed":
            raise RuntimeError(f"CapSolver task failed: {result.get('errorDescription', result)}")

        logger.debug("Task status: %s — waiting...", status)

    raise RuntimeError(f"CapSolver timeout after {timeout}s")
