"""
WhatsApp notification via webhook.

Supports multiple backends:
1. Custom webhook (e.g., your own WhatsApp bot API)
2. Twilio WhatsApp API
3. CallMeBot (free, no setup)
"""

import os
import urllib.request
import urllib.parse
import json


NOTIFY_METHOD = os.environ.get("NOTIFY_METHOD", "webhook")  # webhook, twilio, callmebot
WEBHOOK_URL = os.environ.get("WHATSAPP_WEBHOOK_URL", "")
WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "")

# Twilio config
TWILIO_SID = os.environ.get("TWILIO_SID", "")
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN", "")
TWILIO_FROM = os.environ.get("TWILIO_FROM", "")

# CallMeBot config (free)
CALLMEBOT_API_KEY = os.environ.get("CALLMEBOT_API_KEY", "")


def send_whatsapp(message: str) -> bool:
    """Send a WhatsApp notification using the configured method."""
    print(f"[NOTIFY] Sending via {NOTIFY_METHOD}: {message[:100]}...")

    try:
        if NOTIFY_METHOD == "webhook":
            return _send_webhook(message)
        elif NOTIFY_METHOD == "twilio":
            return _send_twilio(message)
        elif NOTIFY_METHOD == "callmebot":
            return _send_callmebot(message)
        else:
            print(f"[NOTIFY] Unknown method: {NOTIFY_METHOD}")
            return False
    except Exception as e:
        print(f"[NOTIFY] Error: {e}")
        return False


def _send_webhook(message: str) -> bool:
    """Send via custom webhook (POST JSON)."""
    if not WEBHOOK_URL:
        print("[NOTIFY] WHATSAPP_WEBHOOK_URL not set")
        return False

    data = json.dumps({
        "to": WHATSAPP_NUMBER,
        "text": message,
    }).encode("utf-8")

    req = urllib.request.Request(
        WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    print(f"[NOTIFY] Webhook response: {resp.status}")
    return resp.status == 200


def _send_twilio(message: str) -> bool:
    """Send via Twilio WhatsApp API."""
    if not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM, WHATSAPP_NUMBER]):
        print("[NOTIFY] Twilio config incomplete")
        return False

    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json"
    data = urllib.parse.urlencode({
        "From": f"whatsapp:{TWILIO_FROM}",
        "To": f"whatsapp:+{WHATSAPP_NUMBER}",
        "Body": message,
    }).encode("utf-8")

    # Basic auth
    import base64
    auth = base64.b64encode(f"{TWILIO_SID}:{TWILIO_TOKEN}".encode()).decode()

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Authorization": f"Basic {auth}"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    print(f"[NOTIFY] Twilio response: {resp.status}")
    return resp.status in (200, 201)


def _send_callmebot(message: str) -> bool:
    """Send via CallMeBot (free WhatsApp API - https://www.callmebot.com)."""
    if not WHATSAPP_NUMBER or not CALLMEBOT_API_KEY:
        print("[NOTIFY] CallMeBot config incomplete. Get API key at https://www.callmebot.com/blog/free-api-whatsapp-messages/")
        return False

    encoded_msg = urllib.parse.quote(message)
    url = (
        f"https://api.callmebot.com/whatsapp.php"
        f"?phone={WHATSAPP_NUMBER}"
        f"&text={encoded_msg}"
        f"&apikey={CALLMEBOT_API_KEY}"
    )

    req = urllib.request.Request(url, method="GET")
    resp = urllib.request.urlopen(req, timeout=15)
    print(f"[NOTIFY] CallMeBot response: {resp.status}")
    return resp.status == 200


def format_results(results: list) -> str:
    """Format checker results into a WhatsApp message."""
    lines = ["🇯🇵 *VFS Japan Visa Slot Update*\n"]

    has_availability = False
    for r in results:
        if r["available"]:
            has_availability = True
            lines.append(
                f"✅ *{r['centre']}*\n"
                f"   Earliest slot: *{r['earliest_date']}*"
            )
        else:
            lines.append(f"❌ {r['centre']}: No slots")

    lines.append(f"\n🕐 Checked: {results[0]['checked_at'][:19]}")

    if has_availability:
        lines.append("\n⚡ Book now at: https://visa.vfsglobal.com/are/en/jpn/login")

    return "\n".join(lines)
