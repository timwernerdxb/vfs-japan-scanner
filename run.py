#!/usr/bin/env python3
"""
VFS Japan Visa Appointment Slot Checker

Checks for available appointment slots at configured VFS centres
and sends WhatsApp notifications when slots are found.

Usage:
    python run.py                  # Check and notify only if slots found
    python run.py --always-notify  # Always send notification with results
    python run.py --dry-run        # Check but don't send notifications
"""

import asyncio
import sys

from scanner.vfs_checker import main as check_slots
from scanner.notifier import send_whatsapp, format_results


async def run():
    always_notify = "--always-notify" in sys.argv
    dry_run = "--dry-run" in sys.argv

    print("=" * 60)
    print("VFS Japan Visa Slot Checker")
    print("=" * 60)

    # Run the checker
    results = await check_slots()

    if not results:
        print("\n[WARN] No results returned")
        return

    # Check if any slots are available
    has_availability = any(r["available"] for r in results)

    if has_availability:
        print("\n🎉 SLOTS FOUND! Sending notification...")
    else:
        print("\nNo slots available at any centre.")

    # Send notification
    if dry_run:
        message = format_results(results)
        print(f"\n[DRY RUN] Would send:\n{message}")
    elif has_availability or always_notify:
        message = format_results(results)
        success = send_whatsapp(message)
        if success:
            print("[OK] Notification sent!")
        else:
            print("[WARN] Failed to send notification")
            # Print message to stdout so GitHub Actions logs capture it
            print(f"\nMessage:\n{message}")

    # Exit with code 0 if slots found (for GitHub Actions)
    if has_availability:
        # Write to GitHub Actions output if available
        github_output = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith("/") else None
        print("\n✅ Appointment slots are available!")


if __name__ == "__main__":
    asyncio.run(run())
