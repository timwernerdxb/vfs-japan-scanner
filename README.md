# VFS Japan Visa Slot Scanner

Automated appointment slot checker for Japan visa applications via VFS Global (UAE).

Runs on GitHub Actions every 30 minutes and sends a WhatsApp notification when slots open up.

## How it works

1. Logs into VFS Global using Playwright (headless browser)
2. Checks appointment availability for configured centres
3. Sends a WhatsApp alert if slots are found
4. Captures API endpoints for potential direct-API optimization

## Centres checked

- Japan VAC - TEL - Dubai Silicon Oasis
- Japan Visa Application Centre, Dubai

## Setup

### 1. Fork/clone this repo

### 2. Add GitHub Secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description |
|--------|-------------|
| `VFS_EMAIL` | Your VFS Global login email |
| `VFS_PASSWORD` | Your VFS Global password |
| `WHATSAPP_NUMBER` | Your WhatsApp number (with country code, no +) |

### 3. Choose a notification method

Set the `NOTIFY_METHOD` variable in **Settings → Variables → Actions**:

#### Option A: CallMeBot (free, easiest)
1. Send "I allow callmebot to send me messages" to +34 644 71 98 38 on WhatsApp
2. You'll get an API key
3. Add `CALLMEBOT_API_KEY` to secrets
4. Set `NOTIFY_METHOD` = `callmebot`

#### Option B: Custom webhook
1. Set `WHATSAPP_WEBHOOK_URL` to your bot's API endpoint
2. Set `NOTIFY_METHOD` = `webhook`

#### Option C: Twilio
1. Add `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM` to secrets
2. Set `NOTIFY_METHOD` = `twilio`

### 4. Enable the workflow

The GitHub Action runs every 30 minutes automatically. You can also trigger it manually from the Actions tab.

## Local development

```bash
pip install -r requirements.txt
playwright install chromium

export VFS_EMAIL="your@email.com"
export VFS_PASSWORD="yourpassword"

python run.py --dry-run
```

## Known limitations

- **Cloudflare CAPTCHA**: The Turnstile challenge may not always auto-solve in headless mode. If login fails consistently, you may need to add a CAPTCHA solving service.
- **Rate limiting**: VFS may temporarily block your account if requests are too frequent. The 30-minute interval is a safe default.
- **Session expiry**: Each run does a fresh login, so session expiry is not an issue.

## Customization

Edit `scanner/vfs_checker.py` to change:
- `CENTRES` - which VFS centres to check
- `CATEGORY` / `SUBCATEGORY` - visa type
- The script also discovers API endpoints during each run, logged in the output

---

# Nike.com.br Scheduled Purchase Bot

A separate service in this repo that logs into nike.com.br, waits for a
product to become available at a scheduled drop time, and buys it.

Entry point: `python nike_main.py` (same Docker image as the VFS scanner —
just override the start command on the Railway service).

## Railway env vars

Required:

| Variable | Description | Example |
|----------|-------------|---------|
| `NIKE_EMAIL` | Login email for your nike.com.br account | `you@example.com` |
| `NIKE_PASSWORD` | Account password | `...` |
| `NIKE_PRODUCT_URL` | Full URL of the product page | `https://www.nike.com.br/tenis-...` |
| `NIKE_PRODUCT_SIZE` | Size label exactly as shown on the page | `42` or `10.5` |

Scheduling / behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `NIKE_DROP_TIME` | _(empty → immediate)_ | Local drop time, ISO format (`2026-04-18T10:00:00`). Parsed in `NIKE_TIMEZONE`. |
| `NIKE_TIMEZONE` | `America/Sao_Paulo` | Used when `NIKE_DROP_TIME` has no explicit offset |
| `NIKE_PRE_LOGIN_MINUTES` | `5` | How many minutes before drop to log in |
| `NIKE_REFRESH_INTERVAL_MS` | `800` | Page reload interval once drop window opens |
| `NIKE_MAX_RUNTIME_MINUTES` | `15` | Hard cap on polling/purchase time |
| `NIKE_DRY_RUN` | `true` | If `true`, stop BEFORE the final "Finalizar pedido" click and save a screenshot. Flip to `false` to actually pay. |
| `NIKE_HEADLESS` | `true` | Set to `false` locally to watch the browser |
| `NIKE_USER_AGENT` | _Chrome 133 on Linux_ | Override if needed |
| `NIKE_STORAGE_STATE` | `/tmp/nike_state.json` | Where to persist cookies between runs |

Notifications (reused from the VFS scanner — same Resend account):

| Variable | Description |
|----------|-------------|
| `RESEND_API_KEY` | API key from resend.com |
| `NOTIFY_TO` | Comma-separated recipient emails |
| `NOTIFY_FROM` | Sender, e.g. `Nike Bot <notifications@resend.dev>` |

## Deploying to Railway

1. Create a second service in the same Railway project, pointed at this repo.
2. In the new service's **Settings → Deploy**, override:
   - **Start command**: `python nike_main.py`
3. Add the env vars above.
4. First deploy: keep `NIKE_DRY_RUN=true`. The service will log in, walk to
   the checkout review page, screenshot it, and stop. Review the logs and the
   screenshot before flipping `NIKE_DRY_RUN=false`.

## Local test

```bash
pip install -r requirements.txt
patchright install --with-deps chromium

export NIKE_EMAIL=...
export NIKE_PASSWORD=...
export NIKE_PRODUCT_URL="https://www.nike.com.br/..."
export NIKE_PRODUCT_SIZE="42"
export NIKE_DRY_RUN=true
export NIKE_HEADLESS=false   # watch it run

python nike_main.py
```

## Safety

- `NIKE_DRY_RUN=true` is the default. Nothing is paid until you explicitly
  set it to `false`.
- On dry runs a screenshot of the review page is saved to
  `/tmp/nike-checkout-review.png` so you can verify the cart contents,
  shipping address, and payment method before allowing real submissions.
- `NIKE_MAX_RUNTIME_MINUTES` caps how long the service will keep trying.
