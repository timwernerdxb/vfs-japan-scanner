"""One-off helper: launch the Nike profile and dump cookies as a
Playwright `storage_state` JSON.

Usage:
    python -m nike.export_cookies > /tmp/nike-storage.json

Then paste the contents into Railway as NIKE_STORAGE_STATE_JSON.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from patchright.async_api import async_playwright


async def main() -> None:
    user_data_dir = os.environ.get("NIKE_USER_DATA_DIR", "/tmp/nike-user-data")
    channel = os.environ.get("NIKE_BROWSER_CHANNEL", "chrome")
    async with async_playwright() as pw:
        context = await pw.chromium.launch_persistent_context(
            user_data_dir=user_data_dir,
            channel=channel,
            headless=True,
            no_viewport=True,
            locale="pt-BR",
            timezone_id=os.environ.get("NIKE_TIMEZONE", "America/Sao_Paulo"),
        )
        # storage_state() returns {cookies, origins}. Origins include
        # localStorage — we keep it so Nike's frontend can find any
        # saved-login markers.
        storage = await context.storage_state()
        await context.close()
    json.dump(storage, sys.stdout)


if __name__ == "__main__":
    asyncio.run(main())
