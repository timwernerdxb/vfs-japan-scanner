"""
Email notification via Resend.

Get an API key at: https://resend.com/
"""

import json
import os
from urllib.request import Request, urlopen
from urllib.error import URLError

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
NOTIFY_FROM = os.environ.get("NOTIFY_FROM", "VFS Scanner <notifications@resend.dev>")
NOTIFY_TO = os.environ.get("NOTIFY_TO", "")


def send_notification(message: str, subject: str = None) -> bool:
    """Send an email notification via Resend."""
    if not RESEND_API_KEY or not NOTIFY_TO:
        print("[NOTIFY] Missing RESEND_API_KEY or NOTIFY_TO")
        return False

    if not subject:
        if "SLOTS FOUND" in message.upper() or "AVAILABLE" in message.upper():
            subject = "VFS Portugal: Slots Available!"
        else:
            subject = "VFS Portugal Visa Slot Update"

    print(f"[NOTIFY] Sending email to {NOTIFY_TO}: {subject}")

    body = json.dumps({
        "from": NOTIFY_FROM,
        "to": [addr.strip() for addr in NOTIFY_TO.split(",")],
        "subject": subject,
        "html": message.replace("\n", "<br>"),
    }).encode("utf-8")

    req = Request(
        "https://api.resend.com/emails",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
    )

    try:
        resp = urlopen(req, timeout=15)
        print(f"[NOTIFY] Resend response: {resp.status}")
        return resp.status == 200
    except URLError as e:
        print(f"[NOTIFY] Error: {e}")
        return False


def format_results(results: list) -> str:
    """Format checker results into a notification message."""
    lines = ["<h3>VFS Portugal Visa Slot Update</h3>"]

    has_availability = False
    for r in results:
        if r.get("error"):
            lines.append(f"<p>&#9888;&#65039; {r['centre']}: {r['message']}</p>")
        elif r["available"]:
            has_availability = True
            lines.append(
                f"<p><strong>&#9989; {r['centre']}</strong><br>"
                f"Earliest slot: <strong>{r['earliest_date']}</strong></p>"
            )
        else:
            lines.append(f"<p>&#10060; {r['centre']}: No slots</p>")

    lines.append(f"<p><small>Checked: {results[0]['checked_at'][:19]}</small></p>")

    if has_availability:
        lines.append(
            '<p><a href="https://visa.vfsglobal.com/are/en/prt/login">'
            "Book now at VFS</a></p>"
        )

    return "\n".join(lines)
