#!/usr/bin/env python3
# =============================================================================
# screenshot_worker.py — single-host Playwright screenshot with stealth
#
# Invoked one host at a time by scripts/recon_screenshot.sh. Stdout receives a
# single-line JSON object the orchestrator pipes straight into an ES _update.
# Stderr receives human-readable log lines.
#
# Stealth: bypasses the headless-detection heuristics that gowitness fails on
#   (navigator.webdriver, Chrome plugins, WebGL fingerprint, screen size,
#   permissions API). The orchestrator already filters CDN-fronted hosts (CDN
#   would 403 a request long before any browser fingerprint mattered) so this
#   layer is for everything else.
#
# Output JSON keys:
#   host                 echo of input host
#   url                  final URL after redirects (or original if request failed)
#   screenshot_at        ISO-8601 UTC of capture (or attempt)
#   screenshot_status    ok | blocked | failed | nav-error | timeout
#   screenshot_path      absolute path of the full-size JPEG on disk
#   screenshot_thumb_b64 200x150 JPEG re-encoded as base64 (for ES binary field)
#   screenshot_title     <title> of the final page (truncated 200 chars)
#   screenshot_w / _h    captured viewport dimensions
#   error                error string when screenshot_status != ok
#
# Block detection: thumbnail is downscaled to 10x10 and the per-channel
# max-min spread is computed. <15 means the page is essentially one solid
# colour, which on a screenshot context is almost always a WAF interstitial
# / "access denied" page rendered in flat colour.
# =============================================================================
import argparse
import base64
import datetime as dt
import io
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# ── third-party ────────────────────────────────────────────────────────────
from PIL import Image
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout, Error as PWError

# playwright_stealth has shifted APIs across versions — support old + new.
_stealth_apply = None
try:
    from playwright_stealth import Stealth  # 2.0+
    _stealth_instance = Stealth()

    def _stealth_apply(ctx):
        # 2.x exposes apply_stealth_sync / apply_stealth_async. Try sync first.
        if hasattr(_stealth_instance, "apply_stealth_sync"):
            _stealth_instance.apply_stealth_sync(ctx)
        elif hasattr(_stealth_instance, "apply_sync"):
            _stealth_instance.apply_sync(ctx)
except ImportError:
    try:
        from playwright_stealth import stealth_sync  # 1.x

        def _stealth_apply(ctx):
            stealth_sync(ctx)
    except ImportError:
        _stealth_apply = None  # stealth missing — proceed without it (degraded)


# ── helpers ────────────────────────────────────────────────────────────────
def _log(msg: str) -> None:
    sys.stderr.write(f"[SCREENSHOT] {msg}\n")
    sys.stderr.flush()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_filename(host: str) -> str:
    # Hostnames can already contain only [a-z0-9-.], but defensive sanitation
    # protects against the rare URL-as-host edge case.
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host)[:120]


def _is_solid_color(img_bytes: bytes, threshold: int = 15) -> bool:
    """Return True when the image is so flat it is almost certainly a block page."""
    try:
        with Image.open(io.BytesIO(img_bytes)) as im:
            im = im.convert("RGB").resize((10, 10))
            channels = im.split()
            for ch in channels:
                lo, hi = ch.getextrema()
                if hi - lo >= threshold:
                    return False
            return True
    except Exception:  # pragma: no cover — defensive
        return False


def _make_thumb_b64(full_png_bytes: bytes, w: int = 200, h: int = 150, quality: int = 60) -> str:
    """200x150 JPEG thumbnail, base64-encoded — fits an ES binary field cheaply."""
    with Image.open(io.BytesIO(full_png_bytes)) as im:
        im = im.convert("RGB")
        im.thumbnail((w * 2, h * 2))  # downscale first to speed final resize
        im = im.resize((w, h))
        out = io.BytesIO()
        im.save(out, format="JPEG", quality=quality, optimize=True)
        return base64.b64encode(out.getvalue()).decode("ascii")


def _normalize_url(host_or_url: str) -> str:
    if host_or_url.startswith(("http://", "https://")):
        return host_or_url
    return f"https://{host_or_url}"


# ── main capture ───────────────────────────────────────────────────────────
def capture(
    host: str,
    out_dir: Path,
    nav_timeout_ms: int = 15000,
    settle_ms: int = 1500,
    viewport=(1366, 768),
) -> dict:
    url = _normalize_url(host)
    result = {
        "host": host,
        "url": url,
        "screenshot_at": _utc_now(),
        "screenshot_status": "failed",
        "screenshot_path": "",
        "screenshot_thumb_b64": "",
        "screenshot_title": "",
        "screenshot_w": 0,
        "screenshot_h": 0,
        "error": "",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    disk_path = out_dir / f"{_safe_filename(host)}.jpg"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = browser.new_context(
                viewport={"width": viewport[0], "height": viewport[1]},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                timezone_id="America/Los_Angeles",
                ignore_https_errors=True,
            )
            if _stealth_apply is not None:
                try:
                    _stealth_apply(context)
                except Exception as e:
                    _log(f"stealth apply failed (continuing without): {e}")

            page = context.new_page()
            page.set_default_navigation_timeout(nav_timeout_ms)

            try:
                resp = page.goto(url, wait_until="domcontentloaded")
                page.wait_for_timeout(settle_ms)
            except PWTimeout:
                result["screenshot_status"] = "timeout"
                result["error"] = "navigation timeout"
                browser.close()
                return result
            except PWError as e:
                result["screenshot_status"] = "nav-error"
                result["error"] = str(e)[:200]
                browser.close()
                return result

            try:
                result["url"] = page.url
                result["screenshot_title"] = (page.title() or "")[:200]
            except Exception:
                pass

            try:
                png_bytes = page.screenshot(type="png", full_page=False)
            except PWError as e:
                result["screenshot_status"] = "failed"
                result["error"] = f"screenshot error: {e}"[:200]
                browser.close()
                return result

            browser.close()

        # Persist full-size JPEG to disk (smaller than PNG on disk).
        with Image.open(io.BytesIO(png_bytes)) as im:
            im = im.convert("RGB")
            result["screenshot_w"], result["screenshot_h"] = im.size
            im.save(disk_path, format="JPEG", quality=78, optimize=True)
        result["screenshot_path"] = str(disk_path)

        # ES thumb — small enough to live alongside the doc.
        result["screenshot_thumb_b64"] = _make_thumb_b64(png_bytes)

        # Block detection: examine the captured PNG (richer source than thumb).
        if _is_solid_color(png_bytes):
            result["screenshot_status"] = "blocked"
            result["error"] = "page appears solid colour (WAF interstitial)"
        else:
            result["screenshot_status"] = "ok"

        return result

    except Exception as e:  # last-ditch — never raise
        result["error"] = f"{type(e).__name__}: {e}"[:200]
        return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Single-host Playwright screenshot worker")
    ap.add_argument("host", help="hostname or full URL")
    ap.add_argument(
        "--out-dir",
        default=os.environ.get("SCREENSHOT_DIR", str(Path.home() / "recon" / "screenshots")),
        help="directory for full-size JPEGs",
    )
    ap.add_argument("--nav-timeout", type=int, default=15000, help="ms")
    ap.add_argument("--settle", type=int, default=1500, help="ms post-load idle")
    args = ap.parse_args()

    result = capture(
        host=args.host,
        out_dir=Path(args.out_dir),
        nav_timeout_ms=args.nav_timeout,
        settle_ms=args.settle,
    )
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
