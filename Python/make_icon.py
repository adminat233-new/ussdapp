#!/usr/bin/env python3
"""USSD Manager Pro icon - clean blue/white tech mark.

Rounded blue tile, white USSD chat bubble with menu lines, and soft
signal waves kept fully inside the tile (no clipping). Professional, minimal.
"""
import os
from PIL import Image, ImageDraw

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(OUT_DIR, "ussd.ico")
SS = 4

BG_TOP = (37, 99, 235)
BG_BOT = (29, 78, 216)
WHITE = (255, 255, 255)
ACCENT = (29, 78, 216)


def draw_icon(size):
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # --- rounded-square blue background ---
    margin = int(s * 0.03)
    radius = int(s * 0.20)
    for y in range(margin, s - margin):
        t = (y - margin) / max(1, (s - 2 * margin))
        r = int(BG_TOP[0] + (BG_BOT[0] - BG_TOP[0]) * t)
        g = int(BG_TOP[1] + (BG_BOT[1] - BG_TOP[1]) * t)
        b = int(BG_TOP[2] + (BG_BOT[2] - BG_TOP[2]) * t)
        d.line([(margin, y), (s - margin, y)], fill=(r, g, b, 255))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (margin, margin, s - margin, s - margin), radius=radius, fill=255)
    img.putalpha(mask)

    # --- signal waves: keep fully inside tile ---
    cx, cy = int(s * 0.50), int(s * 0.82)
    for i, rad in enumerate((0.28, 0.20, 0.12)):
        r = int(s * rad)
        width = max(1, int(s * 0.030))
        alpha = 180 - i * 25
        d.arc([cx - r, cy - r, cx + r, cy + r],
              start=205, end=335, fill=(*WHITE, alpha), width=width)

    # --- chat bubble: single clean rounded rect ---
    bx0, by0 = int(s * 0.24), int(s * 0.14)
    bx1, by1 = int(s * 0.92), int(s * 0.56)
    brad = int(s * 0.12)
    d.rounded_rectangle((bx0, by0, bx1, by1), radius=brad, fill=WHITE)

    # clean triangular tail (down-left from bubble), drawn as one shape
    # with the bubble bottom edge so it merges seamlessly
    tail = [
        (int(s * 0.36), by1 - int(s * 0.04)),
        (int(s * 0.30), int(s * 0.72)),
        (int(s * 0.52), by1 - int(s * 0.04)),
    ]
    d.polygon(tail, fill=WHITE)
    # small horizontal lip so tail blends into bubble bottom edge
    d.rectangle((int(s * 0.36), by1 - int(s * 0.05), int(s * 0.52), by1), fill=WHITE)

    # --- three USSD menu lines inside bubble ---
    for frac, lw in ((0.24, 0.50), (0.36, 0.44), (0.48, 0.36)):
        x0 = int(s * 0.32)
        x1 = int(s * (0.32 + lw))
        y = int(s * frac)
        lh = max(1, int(s * 0.050))
        d.rounded_rectangle((x0, y, x1, y + lh), radius=lh // 2, fill=ACCENT)

    # small dot (sender / signal origin) at bubble top-left
    dr = max(1, int(s * 0.030))
    dcx, dcy = int(s * 0.30), int(s * 0.22)
    d.ellipse([dcx - dr, dcy - dr, dcx + dr, dcy + dr], fill=ACCENT)

    return img.resize((size, size), Image.LANCZOS)


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = [draw_icon(sz) for sz in sizes]
    imgs[-1].save(OUT, format="ICO", sizes=[(sz, sz) for sz in sizes],
                  append_images=imgs[:-1])
    draw_icon(256).save(os.path.join(OUT_DIR, "ussd_preview.png"))
    print("Wrote", OUT)


if __name__ == "__main__":
    main()
