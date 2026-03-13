"""
VFS Portugal Visa Appointment Slot Checker

Uses direct API calls with session tokens (JWT + cookies).
Tokens are obtained automatically via auto_login.
"""

import json
import os
import re
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

TOKEN_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "session.json")

API_URL = "https://lift-api.vfsglobal.com/appointment/CheckIsSlotAvailable"

# Centres to check
CENTRES = [
    {
        "name": "Portugal Visa Application Centre, Dubai",
        "vacCode": "DXB",
    },
]

VISA_CATEGORY_CODE = os.environ.get("VFS_VISA_CATEGORY", "STOV")
LOGIN_USER = os.environ.get("VFS_EMAIL", "")


def is_session_valid(session):
    """Test if a session is still valid by making a real API call."""
    if not session or not session.get("authorize"):
        return False
    result = check_slot(session, CENTRES[0])
    return not result.get("error")


def load_session():
    """Load saved session (authorize token, cookies) from file."""
    if not os.path.exists(TOKEN_FILE):
        print(f"[ERROR] No session file found at {TOKEN_FILE}")
        print("Run: python3 refresh_token.py")
        return None
    with open(TOKEN_FILE) as f:
        session = json.load(f)
    print(f"[SESSION] Loaded (captured: {session.get('captured_at', 'unknown')})")
    return session


def check_slot(session, centre):
    """Check slot availability for a single centre via API."""
    centre_name = centre["name"]
    vac_code = centre["vacCode"]
    print(f"\n[CHECK] {centre_name} (vacCode={vac_code})")

    result = {
        "centre": centre_name,
        "available": False,
        "earliest_date": None,
        "message": None,
        "error": False,
        "checked_at": datetime.now().isoformat(),
    }

    login_user = session.get("login_user") or LOGIN_USER
    if not login_user:
        result["message"] = "No login_user in session or VFS_EMAIL env var"
        print(f"[ERROR] {result['message']}")
        return result

    body = json.dumps({
        "countryCode": "are",
        "missionCode": "prt",
        "vacCode": vac_code,
        "visaCategoryCode": VISA_CATEGORY_CODE,
        "roleName": "Individual",
        "loginUser": login_user,
        "payCode": "",
    }).encode("utf-8")

    headers = {
        "accept": "application/json, text/plain, */*",
        "authorize": session["authorize"],
        "content-type": "application/json;charset=UTF-8",
        "origin": "https://visa.vfsglobal.com",
        "referer": "https://visa.vfsglobal.com/",
        "route": "are/en/prt",
        "user-agent": session.get("user_agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/144.0.0.0 Safari/537.36"
        ),
    }

    # Add cookies if available
    if session.get("cookies"):
        headers["cookie"] = session["cookies"]

    # Add clientsource if available
    if session.get("clientsource"):
        headers["clientsource"] = session["clientsource"]

    req = Request(API_URL, data=body, headers=headers, method="POST")

    try:
        resp = urlopen(req, timeout=30)
        resp_body = resp.read().decode("utf-8")
        print(f"[API] Status: {resp.status}")
        print(f"[API] Response: {resp_body[:500]}")

        # Parse response
        try:
            data = json.loads(resp_body)
        except json.JSONDecodeError:
            data = None

        # Check for slot availability in response
        if "no appointment slots" in resp_body.lower():
            result["message"] = "No appointment slots currently available"
            print(f"[CHECK] {centre_name}: NO SLOTS")
        elif "earliest" in resp_body.lower():
            date_match = re.search(r"(\d{2}-\d{2}-\d{4})", resp_body)
            if date_match:
                result["available"] = True
                result["earliest_date"] = date_match.group(1)
                result["message"] = resp_body.strip()
                print(f"[CHECK] {centre_name}: SLOTS AVAILABLE! Earliest: {result['earliest_date']}")
            else:
                result["available"] = True
                result["message"] = resp_body.strip()
                print(f"[CHECK] {centre_name}: SLOTS LIKELY AVAILABLE!")
        elif data and isinstance(data, dict):
            # Handle structured JSON response
            if data.get("IsSlotAvailable") or data.get("isSlotAvailable"):
                result["available"] = True
                result["earliest_date"] = data.get("EarliestDate") or data.get("earliestDate")
                result["message"] = str(data)
                print(f"[CHECK] {centre_name}: SLOTS AVAILABLE!")
            else:
                result["message"] = str(data)
                print(f"[CHECK] {centre_name}: {data}")
        else:
            result["message"] = resp_body[:200]
            print(f"[CHECK] {centre_name}: Unknown response format")

    except HTTPError as e:
        result["error"] = True
        error_body = e.read().decode("utf-8")[:500]
        if e.code == 401:
            result["message"] = "⚠️ Session expired - refresh token needed"
            print(f"[ERROR] 401 Unauthorized - token expired")
        elif e.code == 403:
            result["message"] = "⚠️ Session expired - refresh token needed"
            print(f"[ERROR] 403 Forbidden - Cloudflare block")
        else:
            result["message"] = f"⚠️ HTTP {e.code}: {error_body}"
            print(f"[ERROR] HTTP {e.code}: {error_body}")
    except URLError as e:
        result["error"] = True
        result["message"] = f"⚠️ Network error: {e.reason}"
        print(f"[ERROR] {e.reason}")

    return result


async def main():
    """Run the checker and return results."""
    session = load_session()
    if not session:
        return []

    results = []
    for centre in CENTRES:
        result = check_slot(session, centre)
        results.append(result)

    # Print summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    for r in results:
        status = "AVAILABLE" if r["available"] else "NO SLOTS"
        date_info = f" (earliest: {r['earliest_date']})" if r["earliest_date"] else ""
        print(f"  {r['centre']}: {status}{date_info}")

    return results
