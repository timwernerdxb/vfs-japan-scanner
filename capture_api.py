#!/usr/bin/env python3
"""
One-time script: Opens a visible browser so you can log in manually.
Captures the JWT token and API endpoints used for slot checking.
Saves them to api_config.json for the main checker to use.
"""

import asyncio
import json
from datetime import datetime
from playwright.async_api import async_playwright

VFS_URL = "https://visa.vfsglobal.com/are/en/jpn/login"
captured = {"api_calls": [], "jwt": None}


async def on_response(response):
    url = response.url
    method = response.request.method
    # Capture all API calls to vfsglobal
    if "api" in url.lower() or "visa.vfsglobal" in url.lower():
        try:
            content_type = response.headers.get("content-type", "")
            if "json" in content_type:
                body = await response.json()
                entry = {
                    "url": url,
                    "method": method,
                    "status": response.status,
                    "request_headers": dict(response.request.headers),
                    "response_body": body,
                }
                captured["api_calls"].append(entry)

                # Highlight slot/appointment related calls
                keywords = ["slot", "appointment", "calendar", "schedule", "availability"]
                if any(k in url.lower() for k in keywords):
                    print(f"\n{'='*60}")
                    print(f"SLOT API FOUND: {method} {url}")
                    print(f"Status: {response.status}")
                    print(f"Response: {json.dumps(body, indent=2)[:500]}")
                    print(f"{'='*60}\n")
                else:
                    print(f"[API] {method} {url} ({response.status})")
        except Exception:
            pass


async def main():
    print("=" * 60)
    print("VFS API Capture Tool")
    print("=" * 60)
    print()
    print("A browser window will open. Please:")
    print("1. Solve the CAPTCHA and log in")
    print("2. Navigate to book an appointment")
    print("3. Select a centre, category, and sub-category")
    print("4. Wait for the slot check result")
    print("5. Come back here and press Enter to save")
    print()

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            channel="chrome",  # Use real Chrome instead of Playwright's Chromium
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
        )
        page = await context.new_page()
        page.on("response", on_response)

        await page.goto(VFS_URL)
        print("[BROWSER] Login page opened. Log in manually...\n")

        # Wait for user to log in and navigate
        # Check periodically for JWT
        while True:
            await page.wait_for_timeout(3000)

            # Try to extract JWT
            jwt = await page.evaluate(
                "window.sessionStorage.getItem('JWT') || window.localStorage.getItem('JWT') || ''"
            )
            if jwt and not captured["jwt"]:
                captured["jwt"] = jwt
                print(f"\n[JWT] Token captured! (length: {len(jwt)})")

            # Check if user wants to stop
            try:
                # Keep running until browser is closed
                if page.is_closed():
                    break
            except Exception:
                break

            # Check for slot-related API calls
            slot_calls = [c for c in captured["api_calls"]
                         if any(k in c["url"].lower()
                               for k in ["slot", "appointment", "calendar", "availability"])]
            if slot_calls and captured["jwt"]:
                print(f"\n[DONE] Found {len(slot_calls)} slot API call(s) and JWT token!")
                print("Close the browser or press Ctrl+C to save and exit.")

    # Save results
    output = {
        "captured_at": datetime.now().isoformat(),
        "jwt": captured["jwt"],
        "slot_api_calls": [
            c for c in captured["api_calls"]
            if any(k in c["url"].lower()
                  for k in ["slot", "appointment", "calendar", "availability"])
        ],
        "all_api_calls": [
            {"url": c["url"], "method": c["method"], "status": c["status"]}
            for c in captured["api_calls"]
        ],
    }

    with open("api_config.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nSaved to api_config.json")
    print(f"  JWT: {'YES' if output['jwt'] else 'NO'}")
    print(f"  Slot API calls: {len(output['slot_api_calls'])}")
    print(f"  Total API calls: {len(output['all_api_calls'])}")


if __name__ == "__main__":
    asyncio.run(main())
