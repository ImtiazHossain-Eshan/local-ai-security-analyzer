import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

DOCS_ASSETS = Path("docs/assets")
DOCS_ASSETS.mkdir(parents=True, exist_ok=True)

async def capture_all():
    async with async_playwright() as p:
        # Launch browser with high DPI for crisp images
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2 # 2x Retina for crystal-clear screenshots
        )
        page = await context.new_page()

        print("[1] Navigating to Sentinel console...")
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_timeout(1000)

        # 1. Capture Ingestion & Landing Screen
        print("[2] Capturing Ingestion Landing Screen...")
        # Click Load Sample to show the staged fixture state
        await page.click("#btnLoadSample")
        await page.wait_for_timeout(800)
        await page.screenshot(
            path=str(DOCS_ASSETS / "screen_ingestion.png"),
            clip={"x": 100, "y": 80, "width": 1240, "height": 550}
        )
        print("    Saved: docs/assets/screen_ingestion.png")

        # 2. Load the verified 56-chunk completed report
        print("[3] Loading verified report REP-5F21A0A2...")
        await page.evaluate('() => window.loadReport("5f21a0a2-6b15-4fdf-84cf-ac1acf4416a4")')
        await page.wait_for_timeout(1500)

        # 3. Capture Executive Overview & Kill Chain Panel
        print("[4] Capturing Executive Dashboard & Kill Chain...")
        report_sec = await page.query_selector("#reportSection")
        if report_sec:
            # Scroll to top of report section
            await report_sec.scroll_into_view_if_needed()
            await page.wait_for_timeout(500)
            await page.screenshot(
                path=str(DOCS_ASSETS / "screen_executive_killchain.png"),
                clip={"x": 60, "y": 70, "width": 1320, "height": 680}
            )
            print("    Saved: docs/assets/screen_executive_killchain.png")

        # 4. Capture Visual Threat Velocity Chart & Gauges
        print("[5] Capturing Visual Threat Velocity Chart & Hardware Gauges...")
        analytics_panel = await page.query_selector(".visual-analytics-grid")
        if analytics_panel:
            await analytics_panel.scroll_into_view_if_needed()
            await page.wait_for_timeout(500)
            await analytics_panel.screenshot(
                path=str(DOCS_ASSETS / "screen_analytics_chart.png")
            )
            print("    Saved: docs/assets/screen_analytics_chart.png")

        # 5. Capture Findings Triage with Firewall Containment
        print("[6] Capturing Correlated Findings & Firewall Containment...")
        findings_panel = await page.query_selector("#findingsPanelContainer")
        if findings_panel:
            await findings_panel.scroll_into_view_if_needed()
            await page.wait_for_timeout(500)
            await page.screenshot(
                path=str(DOCS_ASSETS / "screen_findings_triage.png"),
                clip={"x": 60, "y": 120, "width": 1320, "height": 720}
            )
            print("    Saved: docs/assets/screen_findings_triage.png")

        # 6. Capture Authentic Log Inspector Modal
        print("[7] Capturing Authentic Log Evidence Inspector Modal...")
        await page.evaluate('() => window.inspectEvidenceLine(196)')
        await page.wait_for_timeout(800)
        modal_card = await page.query_selector(".modal-card")
        if modal_card:
            await modal_card.screenshot(
                path=str(DOCS_ASSETS / "screen_log_inspector.png")
            )
            print("    Saved: docs/assets/screen_log_inspector.png")

        await browser.close()
        print("[+] All screenshots captured successfully!")

if __name__ == "__main__":
    asyncio.run(capture_all())
