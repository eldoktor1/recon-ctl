#!/usr/bin/env python3
"""Generate PWA icons (the recon-ui scope-reticle) with Pillow.

Draws at 4x then downscales (LANCZOS) for crisp anti-aliased edges. No SVG
rasterizer needed. Run:  python3 gen_icons.py   (writes to public/icons/)
"""
import os
from PIL import Image, ImageDraw

TEAL = (77, 216, 192)
DARK = (10, 14, 20)
SS = 4  # supersample
OUT = os.path.join(os.path.dirname(__file__), "public", "icons")
os.makedirs(OUT, exist_ok=True)


def _overlay(size):
    return Image.new("RGBA", (size, size), (0, 0, 0, 0))


def draw_icon(size, maskable=False):
    S = size * SS
    base = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # background tile
    bg = _overlay(S)
    d = ImageDraw.Draw(bg)
    if maskable:
        d.rectangle((0, 0, S, S), fill=DARK + (255,))
    else:
        d.rounded_rectangle((0, 0, S - 1, S - 1), radius=int(S * 0.22), fill=DARK + (255,))
    base = Image.alpha_composite(base, bg)

    cx = cy = S / 2
    R = S * (0.30 if maskable else 0.345)      # ring radius (smaller = maskable safe zone)
    ring_w = max(2, int(S * 0.022))
    tick = S * 0.028

    def comp(draw_fn):
        nonlocal base
        ov = _overlay(S)
        draw_fn(ImageDraw.Draw(ov))
        base = Image.alpha_composite(base, ov)

    # radar sweep wedge (top -> right quarter), translucent
    comp(lambda dr: dr.pieslice((cx - R, cy - R, cx + R, cy + R), 270, 360, fill=TEAL + (72,)))
    # sweep leading edge
    comp(lambda dr: dr.line((cx, cy, cx, cy - R), fill=TEAL + (180,), width=max(1, int(S * 0.012))))
    # inner ring (faint)
    r2 = R * 0.55
    comp(lambda dr: dr.ellipse((cx - r2, cy - r2, cx + r2, cy + r2), outline=TEAL + (105,), width=max(1, int(S * 0.014))))
    # outer reticle ring
    comp(lambda dr: dr.ellipse((cx - R, cy - R, cx + R, cy + R), outline=TEAL + (235,), width=ring_w))

    # crosshair ticks + center lock (opaque)
    def ticks(dr):
        w = ring_w
        dr.line((cx, cy - R - tick, cx, cy - R + tick), fill=TEAL + (255,), width=w)
        dr.line((cx, cy + R - tick, cx, cy + R + tick), fill=TEAL + (255,), width=w)
        dr.line((cx - R - tick, cy, cx - R + tick, cy), fill=TEAL + (255,), width=w)
        dr.line((cx + R - tick, cy, cx + R + tick, cy), fill=TEAL + (255,), width=w)
        rd = S * 0.028
        dr.ellipse((cx - rd, cy - rd, cx + rd, cy + rd), fill=TEAL + (255,))
    comp(ticks)

    return base.resize((size, size), Image.LANCZOS)


def main():
    jobs = [
        ("icon-192.png", 192, False),
        ("icon-512.png", 512, False),
        ("icon-maskable-192.png", 192, True),
        ("icon-maskable-512.png", 512, True),
        ("apple-touch-icon.png", 180, True),
    ]
    for name, size, mask in jobs:
        img = draw_icon(size, maskable=mask)
        img.save(os.path.join(OUT, name))
        print("wrote", name)


if __name__ == "__main__":
    main()
