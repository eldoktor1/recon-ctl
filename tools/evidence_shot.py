#!/usr/bin/env python3
"""evidence_shot.py — headless HTML -> PNG for bug-bounty report evidence.

Renders a self-contained evidence HTML sheet to a crisp PNG using the pipeline's
playwright/chromium venv. NO desktop capture, NO personal windows, fully headless
and reproducible — the privacy-safe, lockable way to produce report screenshots
from already-captured PoC data (curl request/response, interactsh OOB, differentials).

Usage:
  ~/recon/venv/screenshot/bin/python tools/evidence_shot.py <input.html> <output.png> [width]

Convention: build <input.html> from the REAL captured evidence only (redact tokens),
one finding per sheet. See docs/knowledge/workflow-evidence-capture.md.
"""
import sys, os
from playwright.sync_api import sync_playwright

def main():
    if len(sys.argv) < 3:
        print("usage: evidence_shot.py <input.html> <output.png> [width]", file=sys.stderr)
        sys.exit(2)
    html = os.path.abspath(sys.argv[1])
    out = os.path.abspath(sys.argv[2])
    width = int(sys.argv[3]) if len(sys.argv) > 3 else 1160
    if not os.path.exists(html):
        print("no such html: " + html, file=sys.stderr); sys.exit(1)
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        pg = b.new_page(viewport={"width": width, "height": 900}, device_scale_factor=2)
        pg.goto("file://" + html)
        pg.wait_for_timeout(250)
        pg.screenshot(path=out, full_page=True)
        b.close()
    print("wrote " + out + " (" + str(os.path.getsize(out)) + " bytes)")

if __name__ == "__main__":
    main()
