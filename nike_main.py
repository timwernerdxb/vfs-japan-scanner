#!/usr/bin/env python3
"""Nike.com.br scheduled purchase bot — Railway entry point.

Flow:
1. Load config from env vars (fail fast if required ones are missing).
2. If NIKE_DROP_TIME is set, sleep until `pre_login_minutes` before drop.
3. Launch stealth browser, log in (or reuse cached session).
4. Wait until drop_time if set, then start polling product page.
5. On availability: add to cart → checkout → (dry_run gate) → confirm.
6. Send a notification email with the outcome.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone

from nike.browser import browser_context
from nike.config import NikeConfig, load_config
from nike.login import login
from nike.purchase import PurchaseOutcome, wait_for_available_and_buy
from scanner.notifier import send_notification

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("nike_main")


async def _sleep_until(target_utc: datetime, label: str) -> None:
    while True:
        now = datetime.now(timezone.utc)
        remaining = (target_utc - now).total_seconds()
        if remaining <= 0:
            return
        # Log every minute, sleep in chunks so we can log progress
        chunk = min(remaining, 60)
        if remaining > 60:
            logger.info("%s in %.0fs (%.1fm)", label, remaining, remaining / 60)
        await asyncio.sleep(chunk)


async def run(cfg: NikeConfig) -> PurchaseOutcome:
    drop = cfg.drop_time_local()
    if drop:
        drop_utc = drop.astimezone(timezone.utc)
        login_at = drop_utc.timestamp() - cfg.pre_login_minutes * 60
        login_dt = datetime.fromtimestamp(login_at, tz=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        if login_dt > now_utc:
            logger.info("Drop at %s local (%s UTC)", drop, drop_utc)
            logger.info("Will log in at %s UTC", login_dt)
            await _sleep_until(login_dt, "Logging in")
    else:
        logger.info("No NIKE_DROP_TIME set — starting immediately")

    async with browser_context(cfg) as (_browser, context, page):
        logger.info("Browser launched, starting login")
        ok = await login(context, page, cfg)
        if not ok:
            return PurchaseOutcome(
                success=False, stage="login", message="Login failed",
                attempts=0, elapsed_seconds=0,
            )

        if drop:
            drop_utc = drop.astimezone(timezone.utc)
            if drop_utc > datetime.now(timezone.utc):
                logger.info("Logged in. Waiting until drop at %s UTC", drop_utc)
                await _sleep_until(drop_utc, "Drop opens")

        outcome = await wait_for_available_and_buy(page, cfg)
        return outcome


def _notify(outcome: PurchaseOutcome, cfg: NikeConfig) -> None:
    subject = (
        "Nike: PURCHASE SUCCESS" if outcome.success and outcome.stage == "submitted"
        else "Nike: checkout review (dry run)" if outcome.success
        else f"Nike: FAILED at {outcome.stage}"
    )
    body = (
        f"<h3>{subject}</h3>"
        f"<p>Product: {cfg.product_url}</p>"
        f"<p>Size: {cfg.product_size}</p>"
        f"<p>Stage: {outcome.stage}</p>"
        f"<p>Attempts: {outcome.attempts}</p>"
        f"<p>Elapsed: {outcome.elapsed_seconds:.1f}s</p>"
        f"<p>Message: {outcome.message}</p>"
        f"<p>Dry run: {cfg.dry_run}</p>"
    )
    send_notification(body, subject=subject)


def main() -> int:
    cfg = load_config()
    errors = cfg.validate()
    if errors:
        for e in errors:
            logger.error("CONFIG: %s", e)
        return 2

    logger.info("Nike purchase bot starting")
    logger.info("  product: %s", cfg.product_url)
    logger.info("  size:    %s", cfg.product_size)
    logger.info("  drop:    %s", cfg.drop_time_local() or "immediate")
    logger.info("  dry_run: %s", cfg.dry_run)
    logger.info("  headless:%s", cfg.headless)

    try:
        outcome = asyncio.run(run(cfg))
    except KeyboardInterrupt:
        logger.info("Interrupted")
        return 130

    logger.info("Outcome: %s", outcome)
    try:
        _notify(outcome, cfg)
    except Exception as e:
        logger.warning("Notification failed: %s", e)

    return 0 if outcome.success else 1


if __name__ == "__main__":
    sys.exit(main())
