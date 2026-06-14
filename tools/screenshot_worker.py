#!/usr/bin/env python3
# =============================================================================
# screenshot_worker.py — single-host Playwright screenshot with anti-bot stealth
#
# Invoked one host at a time by scripts/recon_screenshot.sh. Stdout receives a
# single-line JSON object the orchestrator pipes straight into an ES _update.
# Stderr receives human-readable log lines.
#
# ANTI-BOT POSTURE (recon evidence only — we render the page we are allowed to
# look at; we never solve interactive CAPTCHAs / break auth):
#   1. HEADED under Xvfb when a DISPLAY is present (orchestrator runs us via
#      `xvfb-run`). Headless detection is the strongest bot signal; a real
#      headed browser on a virtual display defeats a whole class of checks that
#      JS-property stealth cannot reach. Falls back to headless if no display.
#   2. REAL CHROME channel (SHOT_CHROME_CHANNEL=chrome) when installed — the
#      bundled Chromium fingerprint (no Widevine, "Chromium"/"HeadlessChrome"
#      UA, different codecs) is what Akamai/DataDome flag. Falls back to bundled
#      Chromium if the channel is unavailable.
#   3. JS-CHALLENGE WAIT — Cloudflare / DDoS-Guard / DataDome interstitials
#      ("Just a moment…") auto-clear in a few seconds with a real-enough
#      browser. We detect the challenge page and patiently wait it out
#      (networkidle + extra settle) before capturing.
#   4. RETRY-ON-BLOCK — if the first pass is a solid-colour block page or a
#      challenge that has not cleared, retry once with maximum patience.
#   + playwright_stealth (navigator.webdriver, plugins, WebGL, permissions) and
#     a hardened context (locale, timezone, client-hint-consistent headers).
#
# The orchestrator already filters CDN-fronted hosts, so this layer is aimed at
# origin bot-walls / WAFs / JS-heavy SPAs that need patience to render.
#
# Output JSON keys:
#   host                 echo of input host
#   url                  final URL after redirects (or original if request failed)
#   screenshot_at        ISO-8601 UTC of capture (or attempt)
#   screenshot_status    ok | blocked | blank | failed | nav-error | timeout
#                          blocked = genuine bot-challenge interstitial
#                          blank   = page rendered but near-empty (no content/title)
#   screenshot_path      absolute path of the full-size JPEG on disk
#   screenshot_thumb_b64 200x150 JPEG re-encoded as base64 (for ES binary field)
#   screenshot_title     <title> of the final page (truncated 200 chars)
#   screenshot_w / _h    captured viewport dimensions
#   screenshot_engine    chrome-headed | chrome-headless | chromium-headed | chromium-headless
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


# A real-Chrome-on-Windows UA, used ONLY for bundled Chromium (whose native UA
# says "Chromium"/"HeadlessChrome" — an instant tell). When we launch the real
# Chrome channel we leave the UA native so it stays consistent with the
# Sec-CH-UA client hints the browser sends (a mismatch is a bigger tell).
_UA_WINDOWS_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Substrings that mark a bot-challenge / interstitial rather than the real page.
_CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser",
    "verifying you are human",
    "verify you are human",
    "enable javascript and cookies",
    "needs to review the security of your connection",
    "attention required",            # Cloudflare 1020 / block
    "cf-chl", "_cf_chl", "challenge-platform", "cf_chl_opt",
    "ddos-guard", "ddosguard",
    "datadome", "px-captcha", "perimeterx", "_px",
    "請稍候", "请稍候",               # "please wait" (CF localized)
    "incapsula incident id",
)


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


def _looks_like_challenge(title: str, html: str) -> bool:
    """Heuristic: does this page look like a bot-wall interstitial, not content?"""
    t = (title or "").lower()
    h = (html or "").lower()[:30000]
    return any(m in t or m in h for m in _CHALLENGE_MARKERS)


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


def _launch_browser(p, headed: bool, channel):
    """Launch chromium (optionally the real Chrome channel) headed or headless.

    Raises PWError when the requested channel/headed mode is unavailable so the
    caller can degrade gracefully.
    """
    args = [
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--window-size=1366,768",
    ]
    if not headed:
        args.append("--disable-gpu")
    kw = {"headless": not headed, "args": args}
    if channel:
        kw["channel"] = channel
    return p.chromium.launch(**kw)


def _context_kwargs(viewport, channel):
    kw = dict(
        viewport={"width": viewport[0], "height": viewport[1]},
        locale="en-US",
        timezone_id="America/Los_Angeles",
        ignore_https_errors=True,
        color_scheme="light",
        device_scale_factor=1,
        extra_http_headers={
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8"),
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        },
    )
    # Only override the UA for bundled Chromium; real Chrome keeps its native,
    # client-hint-consistent UA.
    if not channel:
        kw["user_agent"] = _UA_WINDOWS_CHROME
    return kw


def _single_capture(p, url, viewport, nav_timeout_ms, settle_ms, challenge_wait_ms, headed, channel):
    """One launch + navigation + screenshot. Returns a dict; never raises."""
    out = {"png": None, "status": "failed", "error": "", "url": url,
           "title": "", "challenged": False}
    try:
        browser = _launch_browser(p, headed, channel)
    except PWError as e:
        # Requested channel/headed mode unavailable — signal caller to fall back.
        out["status"] = "launch-error"
        out["error"] = str(e)[:200]
        return out

    try:
        context = browser.new_context(**_context_kwargs(viewport, channel))
        if _stealth_apply is not None:
            try:
                _stealth_apply(context)
            except Exception as e:
                _log(f"stealth apply failed (continuing without): {e}")

        page = context.new_page()
        page.set_default_navigation_timeout(nav_timeout_ms)

        try:
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(settle_ms)
        except PWTimeout:
            out["status"] = "timeout"
            out["error"] = "navigation timeout"
            return out
        except PWError as e:
            out["status"] = "nav-error"
            out["error"] = str(e)[:200]
            return out

        def _read_title_html():
            t, h = "", ""
            try:
                t = page.title() or ""
            except Exception:
                pass
            try:
                h = page.content() or ""
            except Exception:
                pass
            return t, h

        title, html = _read_title_html()

        # JS-challenge wait: a bot-wall interstitial auto-clears with a real
        # browser — wait for the network to settle and the page to repaint.
        if _looks_like_challenge(title, html):
            _log(f"  bot-challenge detected — waiting it out (up to {challenge_wait_ms}ms)")
            try:
                page.wait_for_load_state("networkidle", timeout=challenge_wait_ms)
            except PWTimeout:
                pass
            page.wait_for_timeout(3000)
            title, html = _read_title_html()

        out["challenged"] = _looks_like_challenge(title, html)
        try:
            out["url"] = page.url
        except Exception:
            pass
        out["title"] = title

        try:
            out["png"] = page.screenshot(type="png", full_page=False)
            out["status"] = "ok"
        except PWError as e:
            out["status"] = "failed"
            out["error"] = f"screenshot error: {e}"[:200]
        return out
    except Exception as e:  # defensive — never raise out of a single pass
        out["status"] = "failed"
        out["error"] = f"{type(e).__name__}: {e}"[:200]
        return out
    finally:
        try:
            browser.close()
        except Exception:
            pass


# ── main capture ───────────────────────────────────────────────────────────
def capture(
    host: str,
    out_dir: Path,
    nav_timeout_ms: int = 20000,
    settle_ms: int = 2000,
    challenge_wait_ms: int = 12000,
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
        "screenshot_engine": "",
        "error": "",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    disk_path = out_dir / f"{_safe_filename(host)}.jpg"

    # Headed when a display is available (orchestrator runs us under xvfb-run).
    headed = os.environ.get("SHOT_HEADED", "1" if os.environ.get("DISPLAY") else "0") == "1"
    channel = (os.environ.get("SHOT_CHROME_CHANNEL", "") or "").strip() or None

    best = None
    with sync_playwright() as p:
        for attempt in (0, 1):
            patient = attempt == 1
            s_ms = max(settle_ms, 4500) if patient else settle_ms
            c_ms = challenge_wait_ms + 10000 if patient else challenge_wait_ms

            cap = _single_capture(p, url, viewport, nav_timeout_ms, s_ms, c_ms, headed, channel)

            # Launch fallback: real-Chrome / headed unavailable -> degrade once.
            if cap["status"] == "launch-error" and (headed or channel):
                _log(f"  headed/channel launch failed ({cap['error']}) — "
                     f"falling back to headless bundled chromium")
                headed = False
                channel = None
                cap = _single_capture(p, url, viewport, nav_timeout_ms, s_ms, c_ms, headed, channel)

            best = cap
            if cap["png"] is None:
                # Only a timeout is worth a patient retry; nav/launch errors will not improve.
                if cap["status"] == "timeout" and not patient:
                    _log("  timeout on first pass — retrying with max patience")
                    continue
                break

            blocked = _is_solid_color(cap["png"]) or cap["challenged"]
            if not blocked or patient:
                break
            _log("  blocked/challenge on first pass — retrying with max patience")

    engine = "{}-{}".format("chrome" if channel else "chromium",
                            "headed" if headed else "headless")
    result["screenshot_engine"] = engine

    if best is None or best.get("png") is None:
        result["screenshot_status"] = (best or {}).get("status", "failed")
        result["error"] = (best or {}).get("error", "no capture")
        return result

    result["url"] = best.get("url", url)
    result["screenshot_title"] = (best.get("title") or "")[:200]
    png_bytes = best["png"]

    # Persist full-size JPEG to disk (smaller than PNG on disk) + ES thumb.
    # We keep the image even when blocked so the operator can eyeball the wall.
    try:
        with Image.open(io.BytesIO(png_bytes)) as im:
            im = im.convert("RGB")
            result["screenshot_w"], result["screenshot_h"] = im.size
            im.save(disk_path, format="JPEG", quality=78, optimize=True)
        result["screenshot_path"] = str(disk_path)
        result["screenshot_thumb_b64"] = _make_thumb_b64(png_bytes)
    except Exception as e:
        result["screenshot_status"] = "failed"
        result["error"] = f"encode error: {type(e).__name__}: {e}"[:200]
        return result

    if best.get("challenged"):
        # Genuine bot-wall: the page text matched a challenge interstitial.
        result["screenshot_status"] = "blocked"
        result["error"] = "bot-challenge persisted after wait"
    elif _is_solid_color(png_bytes):
        # Flat render but NOT a challenge -> this is not a bot-wall. It is either
        # a sparse REAL page (has a title — capture it as ok) or an empty shell
        # (no title — mark blank). The old code wrongly called both "blocked",
        # inflating the block count with capturable content (e.g. a one-line app).
        if (result["screenshot_title"] or "").strip():
            result["screenshot_status"] = "ok"
        else:
            result["screenshot_status"] = "blank"
            result["error"] = "near-empty render (no content / no title)"
    else:
        result["screenshot_status"] = "ok"

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Single-host Playwright screenshot worker")
    ap.add_argument("host", help="hostname or full URL")
    ap.add_argument(
        "--out-dir",
        default=os.environ.get("SCREENSHOT_DIR", str(Path.home() / "recon" / "screenshots")),
        help="directory for full-size JPEGs",
    )
    ap.add_argument("--nav-timeout", type=int, default=20000, help="ms")
    ap.add_argument("--settle", type=int, default=2000, help="ms post-load idle")
    ap.add_argument("--challenge-wait", type=int, default=12000,
                    help="ms to wait out a detected bot-challenge")
    args = ap.parse_args()

    result = capture(
        host=args.host,
        out_dir=Path(args.out_dir),
        nav_timeout_ms=args.nav_timeout,
        settle_ms=args.settle,
        challenge_wait_ms=args.challenge_wait,
    )
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
