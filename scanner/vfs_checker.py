"""
VFS Japan Visa Appointment Slot Checker

Uses Playwright to:
1. Login to VFS Global
2. Intercept the API calls made when checking slot availability
3. Extract JWT token for direct API access
4. Check slots for configured centres
"""

import asyncio
import json
import os
import re
import time
from datetime import datetime
from playwright.async_api import async_playwright

# Configuration from environment variables
VFS_EMAIL = os.environ.get("VFS_EMAIL")
VFS_PASSWORD = os.environ.get("VFS_PASSWORD")
VFS_BASE_URL = "https://visa.vfsglobal.com/are/en/jpn"

# Centre configurations to check
CENTRES = [
    {
        "name": "Japan VAC - TEL - Dubai Silicon Oasis",
        "match_text": "Dubai Silicon Oasis",
    },
    {
        "name": "Japan Visa Application Centre, Dubai",
        "match_text": "Application Centre, Dubai",
    },
]

CATEGORY = "E-Visa - *Tourist Single Entry"
CATEGORY_MATCH = "Tourist"
SUBCATEGORY = "Single Entry Tourism General"
SUBCATEGORY_MATCH = "General"


class VFSChecker:
    def __init__(self):
        self.jwt_token = None
        self.api_endpoints = []
        self.results = []

    async def run(self):
        """Main entry point - login and check all centres."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )

            # Intercept network requests to discover API endpoints
            page = await context.new_page()
            page.on("response", self._capture_api_response)

            try:
                await self._login(page)
                await self._extract_jwt(page)

                for centre in CENTRES:
                    result = await self._check_centre(page, centre)
                    self.results.append(result)

            except Exception as e:
                print(f"[ERROR] {e}")
                # Take a screenshot for debugging
                await page.screenshot(path="error_screenshot.png")
                raise
            finally:
                await browser.close()

        return self.results

    async def _login(self, page):
        """Navigate to login page and authenticate."""
        print(f"[{datetime.now()}] Navigating to login page...")
        await page.goto(f"{VFS_BASE_URL}/login", wait_until="networkidle")
        await page.wait_for_timeout(2000)

        # Fill in credentials
        email_input = page.locator('input[type="text"]').first
        password_input = page.locator('input[type="password"]').first

        await email_input.fill(VFS_EMAIL)
        await password_input.fill(VFS_PASSWORD)
        print("[LOGIN] Credentials entered")

        # Wait for Cloudflare Turnstile to resolve
        print("[LOGIN] Waiting for Cloudflare challenge...")
        await page.wait_for_timeout(5000)

        # Check if turnstile succeeded
        try:
            await page.wait_for_selector(
                "text=Success", timeout=15000
            )
            print("[LOGIN] Cloudflare challenge passed")
        except Exception:
            print("[LOGIN] Cloudflare challenge status unclear, attempting login anyway")

        # Click Sign In
        sign_in_button = page.locator("button", has_text="Sign In")
        await sign_in_button.click()
        print("[LOGIN] Sign In clicked")

        # Wait for dashboard to load
        await page.wait_for_url("**/dashboard", timeout=30000)
        print("[LOGIN] Successfully logged in!")

    async def _extract_jwt(self, page):
        """Extract JWT token from session storage."""
        self.jwt_token = await page.evaluate(
            "window.sessionStorage.getItem('JWT')"
        )
        if self.jwt_token:
            print(f"[JWT] Token extracted (length: {len(self.jwt_token)})")
        else:
            # Try alternative storage locations
            self.jwt_token = await page.evaluate(
                "window.localStorage.getItem('JWT')"
            )
            if self.jwt_token:
                print(f"[JWT] Token from localStorage (length: {len(self.jwt_token)})")
            else:
                print("[JWT] WARNING: Could not extract JWT token")

    async def _check_centre(self, page, centre):
        """Check appointment availability for a specific centre."""
        centre_name = centre["name"]
        match_text = centre["match_text"]
        print(f"\n[CHECK] Checking: {centre_name}")

        result = {
            "centre": centre_name,
            "available": False,
            "earliest_date": None,
            "message": None,
            "checked_at": datetime.now().isoformat(),
        }

        try:
            # Navigate to appointment details
            await page.goto(
                f"{VFS_BASE_URL}/application-detail",
                wait_until="networkidle",
            )
            await page.wait_for_timeout(2000)

            # Select Application Centre
            centre_dropdown = page.locator("mat-select").first
            await centre_dropdown.click()
            await page.wait_for_timeout(1000)

            centre_option = page.locator("mat-option", has_text=match_text)
            await centre_option.click()
            await page.wait_for_timeout(1500)

            # Select appointment category
            category_dropdown = page.locator("mat-select").nth(1)
            await category_dropdown.click()
            await page.wait_for_timeout(1000)

            category_option = page.locator(
                "mat-option", has_text=CATEGORY_MATCH
            )
            await category_option.click()
            await page.wait_for_timeout(1500)

            # Select sub-category
            subcategory_dropdown = page.locator("mat-select").nth(2)
            await subcategory_dropdown.click()
            await page.wait_for_timeout(1000)

            subcategory_option = page.locator(
                "mat-option", has_text=SUBCATEGORY_MATCH
            )
            await subcategory_option.click()
            await page.wait_for_timeout(3000)

            # Handle CAPTCHA popup if it appears
            try:
                captcha_success = page.locator("text=Success")
                if await captcha_success.is_visible(timeout=5000):
                    submit_btn = page.locator("button", has_text="Submit")
                    if await submit_btn.is_visible(timeout=2000):
                        await submit_btn.click()
                        await page.wait_for_timeout(3000)
            except Exception:
                pass

            # Check the page content for results
            page_content = await page.content()

            # Check for "no appointment" message
            no_slots = page.locator(
                "text=no appointment slots are currently available"
            )
            if await no_slots.is_visible(timeout=5000):
                result["message"] = "No appointment slots currently available"
                print(f"[CHECK] {centre_name}: NO SLOTS AVAILABLE")
                return result

        except Exception:
            pass

        # Check for earliest available slot message
        try:
            earliest_slot = page.locator("text=Earliest available slot")
            if await earliest_slot.is_visible(timeout=5000):
                slot_text = await earliest_slot.text_content()
                # Extract date from message like "Earliest available slot for 1,2,3,4 Applicants is : 18-02-2026"
                date_match = re.search(r"(\d{2}-\d{2}-\d{4})", slot_text)
                if date_match:
                    result["available"] = True
                    result["earliest_date"] = date_match.group(1)
                    result["message"] = slot_text.strip()
                    print(
                        f"[CHECK] {centre_name}: SLOTS AVAILABLE! "
                        f"Earliest: {result['earliest_date']}"
                    )
                    return result
        except Exception:
            pass

        # Fallback - take screenshot for manual review
        screenshot_name = f"check_{match_text.replace(' ', '_')}.png"
        await page.screenshot(path=screenshot_name)
        result["message"] = f"Could not determine availability. Screenshot saved as {screenshot_name}"
        print(f"[CHECK] {centre_name}: Could not determine - screenshot saved")
        return result

    async def _capture_api_response(self, response):
        """Capture API responses to discover slot-checking endpoints."""
        url = response.url
        if any(
            keyword in url.lower()
            for keyword in ["slot", "appointment", "calendar", "schedule", "availability"]
        ):
            try:
                body = await response.json()
                self.api_endpoints.append(
                    {
                        "url": url,
                        "status": response.status,
                        "method": response.request.method,
                        "headers": dict(response.request.headers),
                        "body": body,
                    }
                )
                print(f"[API DISCOVERED] {response.request.method} {url}")
                print(f"[API RESPONSE] {json.dumps(body, indent=2)[:500]}")
            except Exception:
                pass


async def main():
    """Run the checker and return results."""
    if not VFS_EMAIL or not VFS_PASSWORD:
        print("ERROR: Set VFS_EMAIL and VFS_PASSWORD environment variables")
        return []

    checker = VFSChecker()
    results = await checker.run()

    # Print summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    for r in results:
        status = "AVAILABLE" if r["available"] else "NO SLOTS"
        date_info = f" (earliest: {r['earliest_date']})" if r["earliest_date"] else ""
        print(f"  {r['centre']}: {status}{date_info}")

    # Print discovered API endpoints
    if checker.api_endpoints:
        print("\n" + "=" * 60)
        print("DISCOVERED API ENDPOINTS")
        print("=" * 60)
        for ep in checker.api_endpoints:
            print(f"  {ep['method']} {ep['url']}")

    # Save JWT for potential direct API use
    if checker.jwt_token:
        print(f"\n[JWT] Token available for direct API calls")

    return results


if __name__ == "__main__":
    asyncio.run(main())
