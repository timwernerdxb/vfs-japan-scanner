#!/usr/bin/env python3
"""
Open Chrome to log in to VFS and capture session tokens.

Run this once (or when your session expires) to refresh the auth tokens.
The main checker (run.py) will use the saved session.

Usage:
    python3 refresh_token.py
"""

import asyncio
import json
import os
from datetime import datetime
from playwright.async_api import async_playwright

VFS_URL = "https://visa.vfsglobal.com/are/en/jpn/login"
SESSION_FILE = os.path.join(os.path.dirname(__file__), "session.json")


async def main():
    print("=" * 60)
    print("VFS Session Capture")
    print("=" * 60)
    print()
    print("A Chrome window will open.")
    print("1. Log in to VFS (solve CAPTCHA, enter credentials)")
    print("2. Once you see the dashboard, come back here")
    print("3. The script will auto-detect login and save the session")
    print()

    captured = {
        "authorize": None,
        "clientsource": None,
        "cookies": None,
        "login_user": None,
        "user_agent": None,
        "captured_at": None,
    }

    async with async_playwright() as p:
        # Launch real Chrome
        browser = await p.chromium.launch(
            headless=False,
            channel="chrome",
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
        )
        page = await context.new_page()

        # Remove webdriver flag
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        """)

        # Capture API requests to extract auth headers
        async def on_request(request):
            url = request.url
            if "lift-api.vfsglobal.com" in url:
                headers = request.headers
                if headers.get("authorize") and not captured["authorize"]:
                    captured["authorize"] = headers["authorize"]
                    captured["clientsource"] = headers.get("clientsource", "")
                    captured["user_agent"] = headers.get("user-agent", "")
                    print(f"\n[CAPTURED] authorize token (length: {len(captured['authorize'])})")
                if headers.get("cookie") and not captured["cookies"]:
                    captured["cookies"] = headers["cookie"]
                    print(f"[CAPTURED] cookies")

        page.on("request", on_request)

        await page.goto(VFS_URL)
        print("[BROWSER] Login page opened. Please log in...\n")

        # Wait for dashboard URL (indicates successful login)
        try:
            await page.wait_for_url("**/dashboard", timeout=300000)  # 5 min timeout
            print("\n[LOGIN] Dashboard detected!")
        except Exception:
            print("\n[TIMEOUT] Did not detect dashboard. Checking what was captured...")

        # Extract JWT from session storage
        jwt = await page.evaluate(
            "window.sessionStorage.getItem('JWT') || window.localStorage.getItem('JWT') || ''"
        )
        if jwt:
            captured["authorize"] = jwt
            print(f"[CAPTURED] JWT from storage (length: {len(jwt)})")

        # Extract login email from storage
        login_user = await page.evaluate("""
            window.sessionStorage.getItem('loginUser')
            || window.sessionStorage.getItem('email')
            || window.localStorage.getItem('loginUser')
            || window.localStorage.getItem('email')
            || ''
        """)
        if login_user:
            captured["login_user"] = login_user
            print(f"[CAPTURED] loginUser: {login_user}")

        # Get cookies from browser context
        cookies = await context.cookies()
        cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        if cookie_str:
            captured["cookies"] = cookie_str
            print(f"[CAPTURED] {len(cookies)} cookies from browser")

        # If we still don't have the authorize token, wait for an API call
        if not captured["authorize"]:
            print("\n[WAIT] Navigating to appointment page to capture auth headers...")
            print("Please select a centre and category in the browser.\n")
            try:
                await page.goto("https://visa.vfsglobal.com/are/en/jpn/application-detail")
                # Wait a bit for API calls
                await page.wait_for_timeout(30000)
            except Exception:
                pass

        await browser.close()

    # Save session
    if captured["authorize"]:
        captured["captured_at"] = datetime.now().isoformat()
        with open(SESSION_FILE, "w") as f:
            json.dump(captured, f, indent=2)
        print(f"\n{'='*60}")
        print(f"Session saved to {SESSION_FILE}")
        print(f"  authorize: {'YES' if captured['authorize'] else 'NO'}")
        print(f"  cookies: {'YES' if captured['cookies'] else 'NO'}")
        print(f"  login_user: {captured.get('login_user', 'NOT FOUND')}")
        print(f"{'='*60}")
        print(f"\nYou can now run: python3 run.py --dry-run")
    else:
        print("\n[ERROR] Could not capture auth token.")
        print("Try logging in again and navigating to the appointment page.")


if __name__ == "__main__":
    asyncio.run(main())
