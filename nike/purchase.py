"""Nike.com.br product page polling + checkout flow.

Strategy:
1. Go to product URL. Refresh at refresh_interval_ms until the size is
   selectable (i.e. not disabled / "Esgotado").
2. Click size → click "Comprar" / "Adicionar à sacola".
3. Go to bag → "Finalizar compra".
4. On the payment/review step, if NIKE_DRY_RUN is true we STOP before the
   final "Pagar" / "Finalizar pedido" click, take a screenshot, and return.
5. Otherwise we click the final confirm button.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from patchright.async_api import Page, TimeoutError as PlaywrightTimeout

from nike.config import NikeConfig

logger = logging.getLogger("nike.purchase")


ADD_TO_CART_SELECTORS = [
    'button:has-text("ADICIONAR AO CARRINHO")',
    'button:has-text("Adicionar ao carrinho")',
    'button:has-text("COMPRAR")',
    'button:has-text("Comprar")',
    'button:has-text("ADICIONAR À SACOLA")',
    'button:has-text("Adicionar à sacola")',
    'button[data-testid="add-to-cart"]',
    'button[data-testid="buy-cta"]',
]

GO_TO_BAG_SELECTORS = [
    'a[href*="/carrinho"]',
    'a[href*="/cart"]',
    'button:has-text("IR PARA O CARRINHO")',
    'button:has-text("Ir para o carrinho")',
    'button:has-text("IR PARA A SACOLA")',
    'button:has-text("Ir para a sacola")',
]

CHECKOUT_SELECTORS = [
    'button:has-text("FINALIZAR COMPRA")',
    'button:has-text("Finalizar compra")',
    'a:has-text("Finalizar compra")',
    'button[data-testid="checkout-button"]',
]

FINAL_PAY_SELECTORS = [
    'button:has-text("FINALIZAR PEDIDO")',
    'button:has-text("Finalizar pedido")',
    'button:has-text("PAGAR")',
    'button:has-text("Pagar")',
    'button[data-testid="place-order"]',
]

SOLD_OUT_TEXTS = ["ESGOTADO", "Esgotado", "INDISPONÍVEL", "Indisponível"]


@dataclass
class PurchaseOutcome:
    success: bool
    stage: str
    message: str
    attempts: int
    elapsed_seconds: float


async def _click_first(page: Page, selectors: list[str], timeout_ms: int = 5000) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            await el.wait_for(state="visible", timeout=timeout_ms)
            await el.click()
            logger.info("Clicked %s", sel)
            return True
        except PlaywrightTimeout:
            continue
        except Exception as e:
            logger.debug("Click %s failed: %s", sel, e)
    return False


async def _select_size(page: Page, size: str) -> bool:
    """Try several shapes of size-picker UIs.

    Nike.com.br varies: sometimes it's a radio list, sometimes a grid of
    buttons with the size as text, sometimes inside a '.size-grid' container.
    """
    candidates = [
        f'label:has-text("{size}"):not([aria-disabled="true"])',
        f'button:has-text("{size}"):not([disabled])',
        f'[data-testid="size-{size}"]',
        f'input[value="{size}"]',
    ]
    for sel in candidates:
        try:
            el = page.locator(sel).first
            await el.wait_for(state="visible", timeout=2000)
            # Check if it looks disabled / sold-out
            class_attr = (await el.get_attribute("class")) or ""
            if "disabled" in class_attr.lower() or "soldout" in class_attr.lower():
                logger.info("Size %s visible but marked disabled", size)
                return False
            await el.click()
            logger.info("Selected size %s via %s", size, sel)
            return True
        except PlaywrightTimeout:
            continue
        except Exception as e:
            logger.debug("Size selector %s failed: %s", sel, e)
    return False


async def _page_shows_sold_out(page: Page) -> bool:
    for text in SOLD_OUT_TEXTS:
        try:
            el = page.get_by_text(text, exact=False).first
            if await el.is_visible(timeout=500):
                return True
        except Exception:
            continue
    return False


async def wait_for_available_and_buy(page: Page, cfg: NikeConfig) -> PurchaseOutcome:
    """Refresh product page until target size is buyable, then purchase."""
    start = time.time()
    deadline = start + cfg.max_runtime_minutes * 60
    interval = cfg.refresh_interval_ms / 1000.0
    attempts = 0

    logger.info(
        "Polling %s for size %s (refresh every %sms, max %sm, dry_run=%s)",
        cfg.product_url, cfg.product_size, cfg.refresh_interval_ms,
        cfg.max_runtime_minutes, cfg.dry_run,
    )

    await page.goto(cfg.product_url, wait_until="domcontentloaded", timeout=60000)

    while time.time() < deadline:
        attempts += 1

        # Try to select size
        size_ok = await _select_size(page, cfg.product_size)

        if size_ok:
            logger.info("Size %s selected, attempting add-to-cart", cfg.product_size)
            if await _click_first(page, ADD_TO_CART_SELECTORS, timeout_ms=4000):
                outcome = await _run_checkout(page, cfg, attempts, start)
                return outcome
            logger.info("Add-to-cart button didn't appear; reloading")

        elif await _page_shows_sold_out(page):
            logger.info("[attempt %d] sold out", attempts)
        else:
            logger.info("[attempt %d] size %s not selectable yet", attempts, cfg.product_size)

        await asyncio.sleep(interval)
        try:
            await page.reload(wait_until="domcontentloaded", timeout=30000)
        except PlaywrightTimeout:
            logger.warning("Reload timed out, continuing")

    return PurchaseOutcome(
        success=False,
        stage="polling",
        message=f"Max runtime reached after {attempts} attempts",
        attempts=attempts,
        elapsed_seconds=time.time() - start,
    )


async def _run_checkout(
    page: Page, cfg: NikeConfig, attempts: int, start: float
) -> PurchaseOutcome:
    """Walk from cart confirmation through checkout to final pay button."""
    logger.info("Added to cart — navigating directly to /carrinho")
    await asyncio.sleep(2)
    await page.goto("https://www.nike.com.br/carrinho", wait_until="domcontentloaded", timeout=30000)
    await asyncio.sleep(3)

    if not await _click_first(page, CHECKOUT_SELECTORS, timeout_ms=10000):
        return PurchaseOutcome(
            success=False, stage="bag", message="Could not click checkout",
            attempts=attempts, elapsed_seconds=time.time() - start,
        )

    logger.info("Entered checkout — waiting for review screen")
    await asyncio.sleep(5)

    try:
        await page.screenshot(path="/tmp/nike-checkout-review.png", full_page=True)
        logger.info("Saved checkout screenshot to /tmp/nike-checkout-review.png")
    except Exception as e:
        logger.warning("Could not screenshot: %s", e)

    if cfg.dry_run:
        logger.warning(
            "DRY_RUN=true: stopping before final payment click. "
            "Review /tmp/nike-checkout-review.png — if it looks correct, "
            "set NIKE_DRY_RUN=false and re-run."
        )
        return PurchaseOutcome(
            success=True, stage="review",
            message="Dry run: reached checkout review without clicking final pay",
            attempts=attempts, elapsed_seconds=time.time() - start,
        )

    logger.warning("Submitting final pay button (DRY_RUN off)")
    if not await _click_first(page, FINAL_PAY_SELECTORS, timeout_ms=10000):
        return PurchaseOutcome(
            success=False, stage="review", message="Could not click final pay button",
            attempts=attempts, elapsed_seconds=time.time() - start,
        )

    await asyncio.sleep(5)
    try:
        await page.screenshot(path="/tmp/nike-order-confirm.png", full_page=True)
    except Exception:
        pass

    return PurchaseOutcome(
        success=True, stage="submitted",
        message="Final pay button clicked; see /tmp/nike-order-confirm.png for confirmation",
        attempts=attempts, elapsed_seconds=time.time() - start,
    )
