"""
WhatsApp notification via CallMeBot.

Free API - get your API key at:
https://www.callmebot.com/blog/free-api-whatsapp-messages/
"""

import os
import urllib.request
import urllib.parse

WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "")
CALLMEBOT_API_KEY = os.environ.get("CALLMEBOT_API_KEY", "")


def send_whatsapp(message: str) -> bool:
    """Send a WhatsApp notification via CallMeBot."""
    if not WHATSAPP_NUMBER or not CALLMEBOT_API_KEY:
        print("[NOTIFY] Missing WHATSAPP_NUMBER or CALLMEBOT_API_KEY")
        return False

    print(f"[NOTIFY] Sending via CallMeBot: {message[:100]}...")

    try:
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
    except Exception as e:
        print(f"[NOTIFY] Error: {e}")
        return False


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
