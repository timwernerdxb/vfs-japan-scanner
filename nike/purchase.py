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

# Primary action buttons — matched by semantic class/role/testid first
# (language-independent), with Portuguese text fallbacks.
PRIMARY_ACTION_SELECTORS = [
    'button[data-testid*="continue" i]:not([disabled])',
    'button[data-testid*="checkout" i]:not([disabled])',
    'button[data-testid*="submit" i]:not([disabled])',
    'button[data-testid*="place-order" i]:not([disabled])',
    'button[data-testid*="next" i]:not([disabled])',
    'button[class*="btn-primary"]:not([disabled])',
    'button[class*="primary" i]:not([disabled])',
    'button[class*="nds-btn-primary" i]:not([disabled])',
    'button:has-text("Continuar"):not([disabled])',
    'button:has-text("CONTINUAR"):not([disabled])',
    'button:has-text("Avançar"):not([disabled])',
    'button:has-text("AVANÇAR"):not([disabled])',
    'button:has-text("Finalizar compra"):not([disabled])',
    'button:has-text("FINALIZAR COMPRA"):not([disabled])',
]

# Text that means we've reached the final review/pay step. Matching these
# stops the continue-loop before we accidentally click them.
NEGATIVE_TEXTS = ("cancelar", "voltar", "retornar", "sair", "editar", "remover", "código")

# Text that indicates we've reached the final review/pay step — we stop
# before clicking these unless dry_run=False.
FINAL_PAY_TEXTS = [
    "FINALIZAR PEDIDO",
    "Finalizar pedido",
    "PAGAR AGORA",
    "Pagar agora",
    "CONFIRMAR PEDIDO",
    "Confirmar pedido",
    "REALIZAR PEDIDO",
    "Realizar pedido",
]

FINAL_PAY_SELECTORS = [f'button:has-text("{t}"):not([disabled])' for t in FINAL_PAY_TEXTS]

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
            text = ((await el.text_content()) or "").lower().strip()
            if any(neg in text for neg in NEGATIVE_TEXTS):
                logger.debug("Skipping %s — text %r contains negative keyword", sel, text)
                continue
            await el.click()
            logger.info("Clicked %s (text=%r)", sel, text)
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


async def _is_final_pay_step(page: Page) -> bool:
    """Return True if the page shows a 'final pay / confirm order' button."""
    for t in FINAL_PAY_TEXTS:
        try:
            btn = page.locator(f'button:has-text("{t}")').first
            if await btn.is_visible(timeout=500):
                return True
        except Exception:
            continue
    return False


async def _run_checkout(
    page: Page, cfg: NikeConfig, attempts: int, start: float
) -> PurchaseOutcome:
    """Walk cart → address → shipping → payment → review by clicking
    'Continuar' at each step, until the final pay button appears."""
    logger.info("Added to cart — navigating directly to /carrinho")
    await asyncio.sleep(2)
    await page.goto("https://www.nike.com.br/carrinho", wait_until="domcontentloaded", timeout=30000)
    await asyncio.sleep(3)

    MAX_STEPS = 8
    for step in range(1, MAX_STEPS + 1):
        url = page.url
        logger.info("Checkout step %d — url: %s", step, url)

        if await _is_final_pay_step(page):
            logger.info("Reached final review/pay step at step %d", step)
            break

        if not await _click_first(page, PRIMARY_ACTION_SELECTORS, timeout_ms=8000):
            logger.error("No Continuar button found at step %d (url=%s)", step, url)
            try:
                await page.screenshot(path=f"/tmp/nike-checkout-stuck-{step}.png", full_page=True)
            except Exception:
                pass
            return PurchaseOutcome(
                success=False, stage=f"step-{step}",
                message=f"Stuck at checkout step {step}, url={url}. "
                        f"See /tmp/nike-checkout-stuck-{step}.png",
                attempts=attempts, elapsed_seconds=time.time() - start,
            )

        # Give the next step time to load. Nike checkout is SPA-ish so
        # we wait for network to settle before looking for the next button.
        await asyncio.sleep(2)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except PlaywrightTimeout:
            pass
        await asyncio.sleep(1)
    else:
        return PurchaseOutcome(
            success=False, stage="checkout-loop",
            message=f"Walked {MAX_STEPS} steps without reaching final pay",
            attempts=attempts, elapsed_seconds=time.time() - start,
        )

    try:
        await page.screenshot(path="/tmp/nike-checkout-review.png", full_page=True)
        logger.info("Saved review screenshot to /tmp/nike-checkout-review.png")
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

    await asyncio.sleep(8)
    try:
        await page.screenshot(path="/tmp/nike-order-confirm.png", full_page=True)
    except Exception:
        pass

    return PurchaseOutcome(
        success=True, stage="submitted",
        message="Final pay button clicked; see /tmp/nike-order-confirm.png",
        attempts=attempts, elapsed_seconds=time.time() - start,
    )
