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


# SNKRS drops rotate the CTA text and disabled state is often a grey
# "Disponível em DD/MM" / "Esgotado" / "Notificar-me". We filter those out
# via NEGATIVE_TEXTS and rely on `:not([disabled])` + a visible test.
ADD_TO_CART_SELECTORS = [
    'button[data-testid="add-to-cart"]:not([disabled])',
    'button[data-testid="buy-cta"]:not([disabled])',
    'button[data-testid*="buy" i]:not([disabled])',
    'button[data-testid*="purchase" i]:not([disabled])',
    'button[data-testid*="cart" i]:not([disabled])',
    'button:has-text("ADICIONAR AO CARRINHO"):not([disabled])',
    'button:has-text("Adicionar ao carrinho"):not([disabled])',
    'button:has-text("ADICIONAR À SACOLA"):not([disabled])',
    'button:has-text("Adicionar à sacola"):not([disabled])',
    'button:has-text("Comprar agora"):not([disabled])',
    'button:has-text("COMPRAR AGORA"):not([disabled])',
    'button:has-text("Comprar"):not([disabled])',
    'button:has-text("COMPRAR"):not([disabled])',
    'button:has-text("Garanta o seu"):not([disabled])',
    'button:has-text("GARANTA O SEU"):not([disabled])',
    'button:has-text("Garantir"):not([disabled])',
    'button:has-text("Eu quero"):not([disabled])',
]

# Countdown / pre-drop / sold-out states — do NOT click these even if
# they technically pass the "primary action" selectors.
UNAVAILABLE_BUTTON_TEXTS = (
    "disponível em",      # e.g. "Disponível em 20/04"
    "disponivel em",
    "notificar-me",
    "notifique-me",
    "avise-me",
    "esgotado",
    "indisponível",
    "indisponivel",
    "em breve",
    "ver produto",
)

GO_TO_BAG_SELECTORS = [
    'a[href*="/carrinho"]',
    'a[href*="/cart"]',
    'button:has-text("IR PARA O CARRINHO")',
    'button:has-text("Ir para o carrinho")',
    'button:has-text("IR PARA A SACOLA")',
    'button:has-text("Ir para a sacola")',
]

# Primary action buttons — "next step" buttons (Continuar, Avançar) that
# advance through the checkout funnel. These MUST NOT include anything that
# could submit the order (place-order, finalizar compra, pagar).
PRIMARY_ACTION_SELECTORS = [
    'button[data-testid*="continue" i]:not([disabled])',
    'button[data-testid*="checkout-continue" i]:not([disabled])',
    'button[data-testid*="next" i]:not([disabled])',
    'button:has-text("Continuar"):not([disabled])',
    'button:has-text("CONTINUAR"):not([disabled])',
    'button:has-text("Avançar"):not([disabled])',
    'button:has-text("AVANÇAR"):not([disabled])',
]

# Text that means we've reached the final review/pay step. Matching these
# stops the continue-loop before we accidentally click them.
NEGATIVE_TEXTS = (
    "cancelar", "voltar", "retornar", "sair", "editar", "remover", "código",
    "comprando",        # "Continuar comprando" = continue shopping (goes back)
    "adicionar ao favoritos", "salvar",
    "aplicar cupom", "cupom",
)

# Text that indicates we've reached the final review/pay step — we stop
# before clicking these unless dry_run=False.
FINAL_PAY_TEXTS = [
    "FINALIZAR PEDIDO",
    "Finalizar pedido",
    "Finalizar compra",
    "FINALIZAR COMPRA",
    "PAGAR AGORA",
    "Pagar agora",
    "CONFIRMAR PEDIDO",
    "Confirmar pedido",
    "REALIZAR PEDIDO",
    "Realizar pedido",
]

FINAL_PAY_SELECTORS = [
    'button[data-testid*="place-order" i]:not([disabled])',
    'button[data-testid*="pay" i]:not([disabled])',
    'button[data-testid*="confirm-order" i]:not([disabled])',
    *(f'button:has-text("{t}"):not([disabled])' for t in FINAL_PAY_TEXTS),
]

# Any URL path whose presence means we're on the final review/pay page.
# We treat these as terminal regardless of button text — prevents an
# accidental order submit in dry_run mode.
FINAL_STEP_URL_HINTS = ("/pagamento", "/payment", "/review", "/revisao", "/confirmar")

SOLD_OUT_TEXTS = ["ESGOTADO", "Esgotado", "INDISPONÍVEL", "Indisponível"]


@dataclass
class PurchaseOutcome:
    success: bool
    stage: str
    message: str
    attempts: int
    elapsed_seconds: float


async def _click_first(page: Page, selectors: list[str], timeout_ms: int = 5000) -> bool:
    """Try each selector in turn with a short per-selector timeout.

    `timeout_ms` is the TOTAL budget spread across all selectors — not per
    selector. This avoids the 14-selectors × 8s = 112s worst case.
    """
    per_sel = max(300, timeout_ms // max(1, len(selectors)))
    for sel in selectors:
        try:
            loc = page.locator(sel)
            try:
                await loc.first.wait_for(state="visible", timeout=per_sel)
            except PlaywrightTimeout:
                continue
            count = await loc.count()
            for i in range(count):
                el = loc.nth(i)
                try:
                    if not await el.is_visible(timeout=500):
                        continue
                    text = ((await el.text_content()) or "").lower().strip()
                    if any(neg in text for neg in NEGATIVE_TEXTS):
                        logger.debug(
                            "Skipping match %d of %s (text=%r, negative)",
                            i, sel, text,
                        )
                        continue
                    if any(u in text for u in UNAVAILABLE_BUTTON_TEXTS):
                        logger.info(
                            "Skipping unavailable CTA %s [%d] text=%r",
                            sel, i, text,
                        )
                        continue
                    try:
                        await el.scroll_into_view_if_needed(timeout=2000)
                    except Exception:
                        pass
                    await el.click()
                    logger.info("Clicked %s [%d] (text=%r)", sel, i, text)
                    return True
                except Exception as e:
                    logger.debug("Inner click #%d of %s failed: %s", i, sel, e)
        except Exception as e:
            logger.debug("Outer %s failed: %s", sel, e)
    return False


_TEXT_WALKER_JS = """
(() => {
    const re = /^\\s*continuar(?!\\s+comprando)/i;
    const negRe = /(voltar|cancelar|sair|editar|remover|comprando)/i;
    const cand = [];
    const all = document.querySelectorAll('button, a, [role="button"], div[role="button"], input[type="submit"], input[type="button"]');
    for (const el of all) {
        const t = (el.innerText || el.textContent || el.value || '').trim();
        if (!t || t.length > 60) continue;
        if (negRe.test(t)) continue;
        if (!re.test(t)) continue;
        if (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true') continue;
        const r = el.getBoundingClientRect();
        if (r.width < 4 || r.height < 4) continue;
        cand.push({
            text: t,
            testid: el.getAttribute('data-testid') || '',
            id: el.id || '',
            tag: el.tagName,
            width: Math.round(r.width),
            height: Math.round(r.height),
        });
        el.setAttribute('data-nike-bot-target', '1');
    }
    return cand;
})()
"""


async def _select_default_option(page: Page) -> int:
    """Pick the first option in every radio group that has no selection yet.

    Nike's /checkout SPA stacks several sections (endereço, tipo de entrega,
    pagamento) on the same URL. Each section is a radio group. Continuar
    only activates when EVERY required group has a selection. So on each
    tick we select one-per-group, not just one overall.

    Returns number of groups we just picked a default for.
    """
    try:
        info = await page.evaluate(
            """() => {
                const picked = [];
                // 1. Native radio groups — group by `name`.
                const byName = new Map();
                document.querySelectorAll('input[type="radio"]').forEach(r => {
                    const k = r.name || '__noname__' + (r.id || Math.random());
                    if (!byName.has(k)) byName.set(k, []);
                    byName.get(k).push(r);
                });
                for (const [name, group] of byName) {
                    if (group.some(r => r.checked)) continue;
                    const first = group[0];
                    const label = first.id ? document.querySelector('label[for="' + first.id + '"]') : first.closest('label');
                    const target = label || first;
                    target.setAttribute('data-nike-radio-pick', picked.length.toString());
                    picked.push({
                        kind: 'native',
                        name,
                        count: group.length,
                        text: (label ? (label.innerText||'').trim() : '').slice(0, 60),
                        id: first.id || '',
                    });
                }
                // 2. ARIA radio groups.
                document.querySelectorAll('[role="radiogroup"]').forEach(grp => {
                    const radios = grp.querySelectorAll('[role="radio"]');
                    if (!radios.length) return;
                    const anyChecked = [...radios].some(r => r.getAttribute('aria-checked') === 'true');
                    if (anyChecked) return;
                    const first = radios[0];
                    first.setAttribute('data-nike-radio-pick', picked.length.toString());
                    picked.push({
                        kind: 'aria',
                        count: radios.length,
                        text: (first.innerText||'').trim().slice(0, 60),
                    });
                });
                return picked;
            }"""
        )
        if not info:
            return 0
        logger.info("_select_default_option: %d unchecked group(s)", len(info))
        for i, item in enumerate(info):
            logger.info("  [%d] %s", i, item)
        clicked_count = 0
        for i, item in enumerate(info):
            try:
                el = page.locator(f'[data-nike-radio-pick="{i}"]').first
                try:
                    await el.scroll_into_view_if_needed(timeout=1500)
                except Exception:
                    pass
                await el.click()
                clicked_count += 1
                await asyncio.sleep(0.3)
            except Exception as e:
                logger.warning("  [%d] click failed: %s", i, e)
        try:
            await page.evaluate(
                """() => document.querySelectorAll('[data-nike-radio-pick]').forEach(e => e.removeAttribute('data-nike-radio-pick'))"""
            )
        except Exception:
            pass
        if clicked_count:
            logger.info("Clicked %d default option(s)", clicked_count)
            await asyncio.sleep(1)
        return clicked_count
    except Exception as e:
        logger.debug("_select_default_option failed: %s", e)
        return 0


async def _click_continuar_by_text(page: Page) -> bool:
    """Last-resort: walk every frame for a visible 'Continuar' element
    (not 'Continuar comprando') and click it.

    Handles cases where the primary button:
      - is below the fold
      - is an <a>/<div role=button>, not a <button>
      - has unusual class names
      - is in a nested iframe (Nike's cart summary / payment widgets)
    """
    frames = page.frames
    logger.info("Text-walker searching %d frame(s) for 'Continuar'", len(frames))
    for i, frame in enumerate(frames):
        try:
            cand = await frame.evaluate(_TEXT_WALKER_JS)
        except Exception as e:
            logger.debug("  frame[%d] (%s) eval failed: %s", i, frame.url[:60], e)
            continue
        if not cand:
            continue
        logger.info("  frame[%d] url=%s found %d candidate(s):", i, frame.url[:80], len(cand))
        for c in cand:
            logger.info("    %s text=%r testid=%r id=%r size=%dx%d",
                        c["tag"], c["text"], c["testid"], c["id"], c["width"], c["height"])
        try:
            el = frame.locator('[data-nike-bot-target="1"]').first
            try:
                await el.scroll_into_view_if_needed(timeout=2000)
            except Exception:
                pass
            await el.click()
            logger.info("Clicked Continuar via text-walker (frame %d)", i)
            try:
                await frame.evaluate(
                    """() => document.querySelectorAll('[data-nike-bot-target]').forEach(e => e.removeAttribute('data-nike-bot-target'))"""
                )
            except Exception:
                pass
            return True
        except Exception as e:
            logger.warning("  frame[%d] click failed: %s", i, e)
            continue
    return False


async def _dump_visible_buttons(page: Page, tag: str) -> None:
    """Log every visible button/link's text — used when stuck to debug."""
    try:
        texts = await page.evaluate(
            """() => {
                const out = [];
                const els = document.querySelectorAll('button, a[role="button"], a[href]');
                for (const el of els) {
                    const r = el.getBoundingClientRect();
                    if (r.width < 2 || r.height < 2) continue;
                    const style = getComputedStyle(el);
                    if (style.display === 'none' || style.visibility === 'hidden') continue;
                    const t = (el.innerText || el.textContent || '').trim().slice(0, 80);
                    if (!t) continue;
                    out.push({
                        tag: el.tagName,
                        text: t,
                        href: el.getAttribute('href') || '',
                        testid: el.getAttribute('data-testid') || '',
                        disabled: el.hasAttribute('disabled'),
                        cls: (el.getAttribute('class') || '').slice(0, 80),
                    });
                }
                return out.slice(0, 40);
            }"""
        )
        logger.info("[%s] visible buttons/links (%d):", tag, len(texts))
        for t in texts:
            logger.info(
                "  %s%s text=%r testid=%r href=%r cls=%r",
                t["tag"], " DISABLED" if t["disabled"] else "",
                t["text"], t["testid"], t["href"], t["cls"],
            )
    except Exception as e:
        logger.warning("Could not dump buttons (%s): %s", tag, e)


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


async def _dismiss_cookie_banner(page: Page) -> bool:
    """Nike's 'Dados de Navegação' (cookies) banner overlays the checkout
    and blocks clicks on underlying UI. Click 'Aceitar' if present."""
    selectors = [
        'button:has-text("Aceitar"):not([disabled])',
        'button:has-text("ACEITAR"):not([disabled])',
        'button:has-text("Aceitar todos"):not([disabled])',
        'button[aria-label*="Aceitar" i]:not([disabled])',
        'button[data-testid*="accept" i]:not([disabled])',
    ]
    for sel in selectors:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=400):
                await el.click()
                logger.info("Dismissed cookie banner via %s", sel)
                await asyncio.sleep(0.5)
                return True
        except Exception:
            continue
    return False


async def _clear_cart(page: Page) -> None:
    """Navigate to /carrinho and remove every item so we start fresh."""
    logger.info("Clearing cart before purchase")
    try:
        await page.goto("https://www.nike.com.br/carrinho", wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        logger.warning("Could not load cart for clearing: %s", e)
        return
    await asyncio.sleep(2)
    for _ in range(15):
        # Find a trash/remove button. Nike uses a small icon button with
        # aria-label 'Remover produto' or a data-testid containing 'remove'.
        removed = await page.evaluate(
            """() => {
                const sels = [
                    'button[aria-label*="Remover" i]',
                    'button[aria-label*="Excluir" i]',
                    'button[data-testid*="remove" i]',
                    'button[data-testid*="delete" i]',
                    'button[data-testid*="trash" i]',
                ];
                for (const s of sels) {
                    const el = document.querySelector(s);
                    if (el && !el.disabled) {
                        el.setAttribute('data-nike-trash-target', '1');
                        return s;
                    }
                }
                return null;
            }"""
        )
        if not removed:
            logger.info("Cart is empty")
            return
        try:
            el = page.locator('[data-nike-trash-target="1"]').first
            await el.scroll_into_view_if_needed(timeout=1500)
            await el.click()
            logger.info("Removed one cart item (via %s)", removed)
            await page.evaluate(
                """() => document.querySelectorAll('[data-nike-trash-target]').forEach(e => e.removeAttribute('data-nike-trash-target'))"""
            )
            await asyncio.sleep(1.5)
            # Confirmation dialog may appear — accept it if "Sim"/"Confirmar".
            for conf in ['button:has-text("Sim"):not([disabled])', 'button:has-text("Confirmar"):not([disabled])', 'button:has-text("Remover"):not([disabled])']:
                try:
                    b = page.locator(conf).first
                    if await b.is_visible(timeout=600):
                        await b.click()
                        logger.info("Confirmed removal via %s", conf)
                        await asyncio.sleep(1)
                        break
                except Exception:
                    continue
        except Exception as e:
            logger.warning("Remove-item click failed: %s", e)
            break


async def _find_product_via_search(page: Page, query: str, deadline: float) -> bool:
    """Use Nike's search box to locate a product by name. Clicks the first
    non-ad product tile. Retries until `deadline` (epoch seconds) in case
    the product isn't indexed yet (e.g. running before a drop).

    Returns True when a product tile has been clicked and we're on its PDP.
    """
    logger.info("Searching nike.com.br for %r", query)
    while time.time() < deadline:
        try:
            await page.goto("https://www.nike.com.br/", wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            logger.warning("Could not load homepage for search: %s", e)
            await asyncio.sleep(2)
            continue

        search_input_selectors = [
            'input[data-testid*="search" i]',
            'input[placeholder*="Busca" i]',
            'input[placeholder*="buscar" i]',
            'input[name*="search" i]',
            'input[type="search"]',
            'input[aria-label*="Busca" i]',
        ]
        input_el = None
        for sel in search_input_selectors:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=1200):
                    input_el = el
                    break
            except Exception:
                continue
        if input_el is None:
            # Nike sometimes hides the search box behind a magnifier icon —
            # click the first visible icon with aria-label="Buscar".
            for sel in ['button[aria-label*="Busca" i]', '[data-testid*="search-toggle" i]']:
                try:
                    b = page.locator(sel).first
                    if await b.is_visible(timeout=800):
                        await b.click()
                        await asyncio.sleep(0.5)
                        break
                except Exception:
                    continue
            for sel in search_input_selectors:
                try:
                    el = page.locator(sel).first
                    if await el.is_visible(timeout=1200):
                        input_el = el
                        break
                except Exception:
                    continue
        if input_el is None:
            logger.warning("Could not find search input; falling back to /busca URL")
            import urllib.parse as _u
            try:
                await page.goto(
                    f"https://www.nike.com.br/busca?query={_u.quote(query)}",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
            except Exception as e:
                logger.warning("Fallback /busca failed: %s", e)
                await asyncio.sleep(2)
                continue
        else:
            try:
                await input_el.fill("")
                await input_el.fill(query)
                await input_el.press("Enter")
            except Exception as e:
                logger.warning("Search input fill failed: %s", e)
                continue
        await asyncio.sleep(2)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except PlaywrightTimeout:
            pass

        # Click the first product tile.
        tile_selectors = [
            'a[data-testid*="product-card" i][href*="/"]',
            'a[data-testid*="product-link" i]',
            'a[data-testid*="produto" i]',
            'a.ProductCard[href*="/"]',
            'a[href*="/"][href*=".html"]',
        ]
        for sel in tile_selectors:
            try:
                tile = page.locator(sel).first
                if await tile.is_visible(timeout=1500):
                    href = await tile.get_attribute("href")
                    logger.info("Clicking first search result (%s): %s", sel, href)
                    await tile.scroll_into_view_if_needed(timeout=2000)
                    await tile.click()
                    await asyncio.sleep(2)
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=15000)
                    except PlaywrightTimeout:
                        pass
                    return True
            except Exception as e:
                logger.debug("Tile %s failed: %s", sel, e)
                continue
        logger.info("No product tiles found for %r — retrying in 5s", query)
        await asyncio.sleep(5)
    return False


async def wait_for_available_and_buy(page: Page, cfg: NikeConfig) -> PurchaseOutcome:
    """Refresh product page until target size is buyable, then purchase."""
    start = time.time()
    deadline = start + cfg.max_runtime_minutes * 60
    interval = cfg.refresh_interval_ms / 1000.0
    attempts = 0

    target_desc = cfg.product_url or f"search={cfg.search_query!r}"
    logger.info(
        "Polling %s for size %s (refresh every %sms, max %sm, dry_run=%s)",
        target_desc, cfg.product_size, cfg.refresh_interval_ms,
        cfg.max_runtime_minutes, cfg.dry_run,
    )

    # Start clean so we don't end up with N copies from prior runs.
    await _clear_cart(page)

    if cfg.product_url:
        await page.goto(cfg.product_url, wait_until="domcontentloaded", timeout=60000)
    else:
        ok = await _find_product_via_search(page, cfg.search_query, deadline)
        if not ok:
            return PurchaseOutcome(
                success=False, stage="search",
                message=f"Could not find {cfg.search_query!r} via search before deadline",
                attempts=0, elapsed_seconds=time.time() - start,
            )

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
    """Return True if the page is the final review/pay step — either by
    URL (/pagamento, /review, /confirmar) or by a visible final-pay button.
    """
    url = (page.url or "").lower()
    if any(h in url for h in FINAL_STEP_URL_HINTS):
        return True
    for sel in FINAL_PAY_SELECTORS:
        try:
            if await page.locator(sel).first.is_visible(timeout=300):
                return True
        except Exception:
            continue
    return False


CVV_INPUT_SELECTORS = [
    'input[data-testid*="cvv" i]',
    'input[id*="cvv" i]',
    'input[name*="cvv" i]',
    'input[aria-label*="CVV" i]',
    'input[aria-label*="código de segurança" i]',
    'input[placeholder*="CVV" i]',
    'input[placeholder*="código" i][placeholder*="segurança" i]',
]


async def _fill_cvv_if_needed(page: Page, cvv: str) -> bool:
    """On the payment page, fill the CVV input if one is visible."""
    if not cvv:
        return False
    for sel in CVV_INPUT_SELECTORS:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=400):
                try:
                    await el.scroll_into_view_if_needed(timeout=1000)
                except Exception:
                    pass
                await el.click()
                await el.fill(cvv)
                logger.info("Filled CVV via %s", sel)
                return True
        except Exception:
            continue
    return False


async def _select_installments(page: Page, preferred: int = 3) -> bool:
    """Pick a value from the installments (parcelas) dropdown.

    Prefers `preferred` if available, falls back to 1. If no dropdown
    exists, returns False (not an error).
    """
    select_candidates = [
        'select[data-testid*="parcel" i]',
        'select[data-testid*="installment" i]',
        'select[id*="parcel" i]',
        'select[name*="parcel" i]',
        'select[aria-label*="parcel" i]',
    ]
    for sel in select_candidates:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=400):
                options = await el.evaluate(
                    """(s) => [...s.options].map(o => ({
                        value: o.value, text: (o.innerText || '').trim(), disabled: o.disabled
                    }))"""
                )
                logger.info("Installments options: %s", options)
                want = [str(preferred), f"{preferred}x", f"{preferred} x"]
                # Try preferred first, then 1.
                for val in want + ["1", "1x", "1 x"]:
                    for o in options:
                        if o["disabled"]:
                            continue
                        if o["value"].strip() == val or o["text"].lower().startswith(val.lower()):
                            await el.select_option(value=o["value"])
                            logger.info("Selected installments: %s (text=%r)", o["value"], o["text"])
                            return True
        except Exception as e:
            logger.debug("Installments selector %s failed: %s", sel, e)
            continue
    logger.debug("No installments dropdown found")
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

    MAX_STEPS = 12
    # Content-hash based stuck detector. Nike's /checkout is an SPA with
    # multiple sections at the same URL — URL and top heading don't change
    # between steps. We hash the main content's innerText after each
    # Continuar click; if the hash is unchanged AND we didn't just select
    # any new radio, treat as stuck and reload.
    last_content_sig = ""
    stuck_streak = 0
    STUCK_RELOAD_THRESHOLD = 3

    async def _content_signature() -> str:
        try:
            return await page.evaluate(
                """() => {
                    const main = document.querySelector('main') || document.body;
                    const t = (main.innerText || '').replace(/\\s+/g, ' ').trim();
                    // Hash via length+slice fingerprint — cheap and good enough.
                    return t.length + ':' + t.slice(0, 80) + '|' + t.slice(-80);
                }"""
            )
        except Exception:
            return ""

    for step in range(1, MAX_STEPS + 1):
        url = page.url
        logger.info("Checkout step %d — url: %s", step, url)

        # Nike's cookie banner overlays everything and eats clicks.
        await _dismiss_cookie_banner(page)

        if await _is_final_pay_step(page):
            logger.info("Reached final review/pay step at step %d", step)
            break

        # Select defaults for every unselected radio group on the page.
        selected = await _select_default_option(page)

        cur_sig = await _content_signature()
        if cur_sig == last_content_sig and selected == 0 and step > 1:
            stuck_streak += 1
        else:
            stuck_streak = 0
        last_content_sig = cur_sig

        if stuck_streak >= STUCK_RELOAD_THRESHOLD:
            logger.warning("Content unchanged for %d steps — reloading page", stuck_streak)
            try:
                await page.reload(wait_until="domcontentloaded", timeout=30000)
                await asyncio.sleep(3)
            except Exception as e:
                logger.warning("Reload failed: %s", e)
            stuck_streak = 0
            continue

        clicked = await _click_first(page, PRIMARY_ACTION_SELECTORS, timeout_ms=5000)
        if not clicked:
            clicked = await _click_continuar_by_text(page)
        if not clicked:
            logger.info("Step %d: no primary button on first pass, waiting 3s", step)
            await asyncio.sleep(3)
            clicked = await _click_first(page, PRIMARY_ACTION_SELECTORS, timeout_ms=8000)
            if not clicked:
                clicked = await _click_continuar_by_text(page)
        if not clicked:
            logger.error("No primary button found at step %d (url=%s)", step, url)
            await _dump_visible_buttons(page, f"stuck-step-{step}")
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

    # Once on the payment/review step, fill CVV and installments (parcelas)
    # before taking the review screenshot / submitting.
    import os as _os
    cvv = _os.environ.get("NIKE_CVV", "").strip()
    parcelas = int(_os.environ.get("NIKE_PARCELAS", "3") or 3)

    # Clean up any lingering cookie overlay.
    await _dismiss_cookie_banner(page)
    await asyncio.sleep(2)

    # Explicitly select the credit card payment method. Nike's /pagamento
    # renders CVV and parcelas controls only after a method is chosen.
    try:
        card_selectors = [
            'label[for="radio-button-payment-creditCard"]',
            'label:has-text("Cartão de crédito")',
            '[data-testid*="credit-card" i]',
            'input#radio-button-payment-creditCard',
            'input[id*="creditCard" i]',
        ]
        for sel in card_selectors:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=500):
                    await el.scroll_into_view_if_needed(timeout=1500)
                    await el.click()
                    logger.info("Selected credit card via %s", sel)
                    break
            except Exception:
                continue
    except Exception as e:
        logger.debug("Credit-card selection failed: %s", e)

    await asyncio.sleep(2)

    if cvv:
        filled = await _fill_cvv_if_needed(page, cvv)
        if not filled:
            logger.info("CVV input not found (card may be saved with CVV already)")
    else:
        logger.info("NIKE_CVV not set — skipping CVV fill")

    picked = await _select_installments(page, preferred=parcelas)
    if not picked:
        logger.info("Installments select not found — leaving default")

    await asyncio.sleep(1)

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
