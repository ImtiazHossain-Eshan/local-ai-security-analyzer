import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def render():
    svg_path = Path("docs/assets/sentinel_hero.svg").resolve()
    png_path = Path("docs/assets/sentinel_hero.png").resolve()

    svg_content = svg_path.read_text(encoding="utf-8")

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body, html {{
      width: 1200px;
      height: 460px;
      background: #04060a;
      overflow: hidden;
    }}
  </style>
</head>
<body>
  {svg_content}
</body>
</html>"""

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1200, "height": 460}, device_scale_factor=2)
        await page.set_content(html_content, wait_until="networkidle")
        await page.wait_for_timeout(800)
        await page.screenshot(path=str(png_path), clip={"x": 0, "y": 0, "width": 1200, "height": 460})
        await browser.close()

    print(f"[+] Rendered {png_path} ({png_path.stat().st_size} bytes)")

if __name__ == "__main__":
    asyncio.run(render())

