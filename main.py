#!/usr/bin/env python3
"""
VFS Portugal Visa Slot Checker — Railway Worker

Long-running worker that:
1. Logs in automatically via Playwright + CapSolver
2. Checks appointment slots at configurable intervals
3. Re-authenticates when session expires
4. Sends email notifications when slots are found
"""

import asyncio
import logging
import os
import signal
import time

from scanner.auto_login import auto_login
from scanner.vfs_checker import check_slot, is_session_valid, CENTRES
from scanner.notifier import send_notification, format_results

CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL_MINUTES", "20")) * 60
MAX_CONSECUTIVE_ERRORS = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("worker")

running = True


def handle_signal(sig, frame):
    global running
    logger.info("Shutdown signal received, stopping...")
    running = False


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


async def main():
    global running

    logger.info("VFS Portugal Slot Checker starting...")
    logger.info("Check interval: %d minutes", CHECK_INTERVAL // 60)
    logger.info("Centres: %s", ", ".join(c["name"] for c in CENTRES))

    session = None
    consecutive_login_failures = 0

    while running:
        # Login if needed
        if not session:
            try:
                logger.info("Logging in...")
                session = await auto_login()
                logger.info("Login successful (captured: %s)", session.get("captured_at"))
                consecutive_login_failures = 0
            except Exception as e:
                consecutive_login_failures += 1
                logger.error("Login failed (%d/%d): %s",
                             consecutive_login_failures, MAX_CONSECUTIVE_ERRORS, e)
                if consecutive_login_failures >= MAX_CONSECUTIVE_ERRORS:
                    send_notification(
                        f"Login failed {MAX_CONSECUTIVE_ERRORS} times in a row.<br>"
                        "Check CapSolver balance or VFS credentials.",
                        subject="VFS Scanner: Login Failure Alert",
                    )
                    consecutive_login_failures = 0
                await _sleep(300)  # 5 min before retry
                continue

        # Check slots
        logger.info("Checking appointment slots...")
        results = []
        for centre in CENTRES:
            result = check_slot(session, centre)
            results.append(result)

        # Detect auth errors
        auth_errors = [
            r for r in results
            if r.get("error") and any(
                s in str(r.get("message", "")).lower()
                for s in ["401", "403", "expired", "unauthorized"]
            )
        ]

        if auth_errors:
            logger.warning("Auth error detected — will re-login next cycle")
            session = None
            await _sleep(10)
            continue

        # Process results
        has_availability = any(r["available"] for r in results)
        all_errors = all(r.get("error") for r in results)

        if has_availability:
            logger.info("SLOTS FOUND! Sending notification...")
            message = format_results(results)
            success = send_notification(message)
            if success:
                logger.info("Notification sent!")
            else:
                logger.error("Failed to send notification")
        elif all_errors:
            logger.warning("All checks returned errors")
        else:
            logger.info("No slots available")

        # Summary
        for r in results:
            status = "AVAILABLE" if r["available"] else ("ERROR" if r.get("error") else "no slots")
            logger.info("  %s: %s", r["centre"], status)

        # Wait for next check
        logger.info("Next check in %d minutes", CHECK_INTERVAL // 60)
        await _sleep(CHECK_INTERVAL)

    logger.info("Worker stopped.")


async def _sleep(seconds):
    """Interruptible sleep — checks shutdown flag every second."""
    for _ in range(seconds):
        if not running:
            break
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
