#!/usr/bin/env python3
"""
VFS Slot Checker HTTP API

Wraps the proven Patchright + CapSolver login + lift-api slot check
behind a tiny bearer-auth HTTP endpoint. Vera (or any caller) hits
POST /check-slots and gets back availability JSON.

Login is expensive (~30-60s with captcha). The session (JWT + cookies
+ clientsource + cf_clearance) is cached in process memory per
(country, mission, login_user) tuple until the API returns 401/403,
at which point we re-login and retry once.

Env vars required:
  CHECKER_SHARED_SECRET — bearer token callers must send
  VFS_EMAIL, VFS_PASSWORD — login credentials
  CAP_SOLVER_API_KEY — captcha solver
  PROXY_* — residential proxy for login (see scanner/auto_login.py)
"""

import sys
print("[server.py] import starting", flush=True)
sys.stdout.flush()

import asyncio
import hmac
import json
import logging
import os
import time
from datetime import datetime
from typing import Optional

print("[server.py] stdlib imports OK", flush=True)

from starlette.applications import Starlette
print("[server.py] starlette import OK", flush=True)
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from scanner.auto_login import auto_login
print("[server.py] auto_login import OK", flush=True)
from scanner.vfs_checker import check_slot
print("[server.py] vfs_checker import OK", flush=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("server")

CHECKER_SHARED_SECRET = os.environ.get("CHECKER_SHARED_SECRET", "")
SESSION_MAX_AGE_SECONDS = int(os.environ.get("SESSION_MAX_AGE_SECONDS", "1800"))  # 30 min default

# Per-(country, mission, login_user) session cache. Login is expensive; we
# only re-do it when the API rejects the token or the session ages out.
_session_cache: dict[tuple, dict] = {}
# Per-key lock so two concurrent requests for the same account don't both
# trigger a login.
_login_locks: dict[tuple, asyncio.Lock] = {}


def _bearer_ok(request: Request) -> bool:
    if not CHECKER_SHARED_SECRET:
        # Refuse to serve if the operator forgot to configure the secret.
        return False
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    presented = auth.split(" ", 1)[1].strip()
    return hmac.compare_digest(presented, CHECKER_SHARED_SECRET)


def _session_key(country: str, mission: str, login_user: str) -> tuple:
    return (country.lower(), mission.lower(), login_user.lower())


def _session_fresh(session: dict) -> bool:
    captured = session.get("_captured_ts", 0)
    return (time.time() - captured) < SESSION_MAX_AGE_SECONDS


async def _login_with_lock(key: tuple) -> dict:
    """Login under a per-key asyncio lock so concurrent callers coalesce."""
    lock = _login_locks.setdefault(key, asyncio.Lock())
    async with lock:
        # Double-check inside the lock — another coroutine may have logged in.
        cached = _session_cache.get(key)
        if cached and cached.get("authorize") and _session_fresh(cached):
            return cached
        logger.info("Login starting for key=%s", key)
        session = await auto_login()
        session["_captured_ts"] = time.time()
        _session_cache[key] = session
        logger.info(
            "Login complete for key=%s (jwt_len=%d, has_clientsource=%s)",
            key,
            len(session.get("authorize", "")),
            bool(session.get("clientsource")),
        )
        return session


def _check_with_session(session: dict, vac: str) -> dict:
    """Run the synchronous check_slot from scanner/vfs_checker."""
    centre = {"name": f"VAC {vac}", "vacCode": vac}
    return check_slot(session, centre)


def _is_auth_error(result: dict) -> bool:
    msg = str(result.get("message", "")).lower()
    return result.get("error") and any(s in msg for s in ("401", "403", "expired", "unauthorized"))


async def health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


async def check_slots(request: Request) -> JSONResponse:
    if not _bearer_ok(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid json body"}, status_code=400)

    country = (body.get("country") or "are").strip()
    mission = (body.get("mission") or "prt").strip()
    vac = (body.get("vac") or "DXB").strip()
    category = (body.get("category") or "STOV").strip()
    purpose = (body.get("purpose") or "").strip()
    force_relogin = bool(body.get("force_relogin", False))

    login_user = os.environ.get("VFS_EMAIL", "")
    if not login_user:
        return JSONResponse({"error": "server misconfigured: VFS_EMAIL unset"}, status_code=500)

    key = _session_key(country, mission, login_user)
    logger.info(
        "check_slots country=%s mission=%s vac=%s category=%s purpose=%r force_relogin=%s",
        country, mission, vac, category, purpose, force_relogin,
    )

    if force_relogin:
        _session_cache.pop(key, None)

    # We currently only have auto_login wired up for the are/prt path.
    # Refuse anything else explicitly rather than silently using the wrong session.
    if (country.lower(), mission.lower()) != ("are", "prt"):
        return JSONResponse(
            {
                "error": "unsupported_route",
                "supported": [{"country": "are", "mission": "prt"}],
                "note": "Other routes need auto_login.py to be parameterized. "
                        "Open an issue if you need a different country/mission.",
            },
            status_code=400,
        )

    # The current scanner.vfs_checker.check_slot also hardcodes missionCode='prt'
    # and route='are/en/prt' — so vac is the only parameter that matters for now.
    # category is honored via the VFS_VISA_CATEGORY env var fallback inside
    # check_slot; pass it through env-style by temporarily setting it.
    prev_category = os.environ.get("VFS_VISA_CATEGORY")
    os.environ["VFS_VISA_CATEGORY"] = category
    try:
        # 1) Get/refresh session.
        try:
            session = await _login_with_lock(key)
        except Exception as exc:
            logger.exception("Login failed: %s", exc)
            return JSONResponse(
                {"error": "login_failed", "details": str(exc)[:500]},
                status_code=502,
            )

        # 2) Run check.
        result = await asyncio.to_thread(_check_with_session, session, vac)

        # 3) If auth error, force re-login + retry once.
        if _is_auth_error(result):
            logger.warning("Auth error on first attempt — refreshing session")
            _session_cache.pop(key, None)
            try:
                session = await _login_with_lock(key)
            except Exception as exc:
                logger.exception("Re-login failed: %s", exc)
                return JSONResponse(
                    {"error": "relogin_failed", "details": str(exc)[:500]},
                    status_code=502,
                )
            result = await asyncio.to_thread(_check_with_session, session, vac)

    finally:
        if prev_category is None:
            os.environ.pop("VFS_VISA_CATEGORY", None)
        else:
            os.environ["VFS_VISA_CATEGORY"] = prev_category

    # 4) Shape the response.
    return JSONResponse(
        {
            "country": country,
            "mission": mission,
            "vac": vac,
            "category": category,
            "available": bool(result.get("available")),
            "earliest_date": result.get("earliest_date"),
            "message": result.get("message"),
            "error": bool(result.get("error")),
            "checked_at": result.get("checked_at") or datetime.utcnow().isoformat() + "Z",
            "session_age_seconds": int(time.time() - session.get("_captured_ts", time.time())),
            "_audit": {
                "purpose": purpose or None,
                "served_at": datetime.utcnow().isoformat() + "Z",
            },
        }
    )


async def evict_session(request: Request) -> JSONResponse:
    """Force-evict the cached session for the configured account."""
    if not _bearer_ok(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    login_user = os.environ.get("VFS_EMAIL", "")
    removed = []
    for k in list(_session_cache.keys()):
        if k[2] == login_user.lower():
            _session_cache.pop(k, None)
            removed.append(list(k))
    return JSONResponse({"removed_keys": removed})


routes = [
    Route("/health", health, methods=["GET"]),
    Route("/check-slots", check_slots, methods=["POST"]),
    Route("/evict-session", evict_session, methods=["POST"]),
]

app = Starlette(debug=False, routes=routes)
print("[server.py] app built; ready for ASGI", flush=True)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
