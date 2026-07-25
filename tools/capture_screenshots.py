#!/usr/bin/env python3
"""Capture recon-ui screenshots for the README, using the built SPA in DEMO mode.

Demo mode (`?demo=1` / localStorage `recon_demo=1`) renders the whole UI from
synthetic `example.com` fixtures with NO backend token and NO real target data —
safe to publish. Requires: playwright + chromium, and the UI served locally
(default http://127.0.0.1:8787 — `tools/start_ui.sh` or the recon-ui service).

    pip install playwright && python -m playwright install chromium
    python tools/capture_screenshots.py [base_url]

Writes docs/img/{dashboard,leads,lanes,assets,findings}.png.
"""
import pathlib
import sys

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787"
OUT = pathlib.Path(__file__).resolve().parent.parent / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)

PAGES = [
    ("dashboard", "/"),
    ("leads", "/leads"),
    ("lanes", "/lanes"),
    ("assets", "/assets"),
    ("findings", "/findings"),
    ("programs", "/programs"),
]


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 900},
                                  device_scale_factor=2, color_scheme="dark")
        page = ctx.new_page()
        # prime demo mode so client-side route changes keep serving fixtures
        page.goto(f"{BASE}/?demo=1", wait_until="networkidle")
        page.evaluate("() => localStorage.setItem('recon_demo','1')")
        for name, route in PAGES:
            page.goto(f"{BASE}{route}?demo=1", wait_until="networkidle")
            page.wait_for_timeout(1200)  # let charts/lists settle
            dest = OUT / f"{name}.png"
            page.screenshot(path=str(dest))
            print(f"  wrote {dest}")
        browser.close()
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
