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
