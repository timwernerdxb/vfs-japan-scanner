"""
CapSolver Turnstile CAPTCHA solver.

Uses the CapSolver API to solve Cloudflare Turnstile challenges.
Get an API key at: https://www.capsolver.com/
"""

import json
import logging
import os
import time
from urllib.request import Request, urlopen
from urllib.error import URLError

CAPSOLVER_API_KEY = os.environ.get("CAPSOLVER_API_KEY", "")

CAPSOLVER_CREATE_URL = "https://api.capsolver.com/createTask"
CAPSOLVER_RESULT_URL = "https://api.capsolver.com/getTaskResult"

logger = logging.getLogger("captcha_solver")


def solve_turnstile(website_url: str, website_key: str, timeout: int = 120) -> str:
    """
    Solve a Cloudflare Turnstile challenge via CapSolver API.

    Args:
        website_url: The URL of the page with the Turnstile widget.
        website_key: The Turnstile sitekey (usually starts with 0x4...).
        timeout: Max seconds to wait for solution.

    Returns:
        The solved Turnstile token string.

    Raises:
        RuntimeError: If solving fails or times out.
    """
    if not CAPSOLVER_API_KEY:
        raise RuntimeError("CAPSOLVER_API_KEY environment variable not set")

    logger.info("Solving Turnstile for %s (sitekey=%s...)", website_url, website_key[:12])

    # Step 1: Create task
    payload = json.dumps({
        "clientKey": CAPSOLVER_API_KEY,
        "task": {
            "type": "AntiTurnstileTaskProxyLess",
            "websiteURL": website_url,
            "websiteKey": website_key,
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

    # Step 2: Poll for result
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(3)

        poll_payload = json.dumps({
            "clientKey": CAPSOLVER_API_KEY,
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
