"""Open a product URL with the Nike profile and add it to favorites.

Usage:
    python -m nike.add_favorite "https://www.nike.com.br/snkrs/..."
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from patchright.async_api import async_playwright

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("nike.add_favorite")


FAV_SELECTORS = [
    'button:has-text("Salvar como favoritos")',
    'button:has-text("Salvar aos favoritos")',
    'button:has-text("Salvar nos favoritos")',
    'button:has-text("Salvar em favoritos")',
    'button:has-text("Adicionar aos favoritos")',
    'button:has-text("Adicionar a favoritos")',
    'button[class*="FavoritesPDPButton" i]',
]
ALREADY_FAV_SELECTORS = [
    'button:has-text("Remover dos favoritos")',
    'button:has-text("Remover de favoritos")',
    'button:has-text("Salvo nos favoritos")',
    'button:has-text("Salvo como favoritos")',
    'button:has-text("Salvo")',
]


async def main(url: str) -> int:
    user_data_dir = os.environ.get("NIKE_USER_DATA_DIR", "/tmp/nike-user-data")
    channel = os.environ.get("NIKE_BROWSER_CHANNEL", "chrome")
    headless = os.environ.get("NIKE_HEADLESS", "false").lower() in ("1", "true", "yes")

    async with async_playwright() as pw:
        context = await pw.chromium.launch_persistent_context(
            user_data_dir=user_data_dir,
            channel=channel,
            headless=headless,
            no_viewport=True,
            locale="pt-BR",
            timezone_id="America/Sao_Paulo",
        )
        page = context.pages[0] if context.pages else await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=60000)
            await asyncio.sleep(3)

            for sel in ALREADY_FAV_SELECTORS:
                try:
                    if await page.locator(sel).first.is_visible(timeout=800):
                        logger.info("Already favorited (%s)", sel)
                        return 0
                except Exception:
                    continue

            for sel in FAV_SELECTORS:
                try:
                    b = page.locator(sel).first
                    if await b.is_visible(timeout=1500):
                        await b.scroll_into_view_if_needed(timeout=2000)
                        await b.click()
                        logger.info("Clicked favorite button via %s", sel)
                        await asyncio.sleep(2)
                        for v in ALREADY_FAV_SELECTORS:
                            try:
                                if await page.locator(v).first.is_visible(timeout=800):
                                    logger.info("Confirmed favorited (%s)", v)
                                    return 0
                            except Exception:
                                continue
                        logger.warning("Clicked favorite, but confirmation not visible — may still have worked")
                        return 0
                except Exception as e:
                    logger.debug("%s failed: %s", sel, e)

            logger.error("Could not find a favorite button on %s", url)
            try:
                await page.screenshot(path="/tmp/nike-favorite-debug.png", full_page=True)
                logger.info("Screenshot saved to /tmp/nike-favorite-debug.png")
            except Exception:
                pass
            return 1
        finally:
            await context.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python -m nike.add_favorite <url>", file=sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1])))
