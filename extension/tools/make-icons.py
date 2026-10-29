#!/usr/bin/env python3
"""Generate the Scouter Web Guard extension icons (pure stdlib — no Pillow/SVG deps).

Draws a shield with a check mark, supersampled for anti-aliasing and written as transparent RGBA
PNGs at the sizes the Chrome/Firefox manifests reference. Run from the extension/ dir:
    python3 tools/make-icons.py
"""
import math
import os
import struct
import zlib

SIZES = [16, 32, 48, 128]
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "icons")
TOP = (0x3b, 0x82, 0xf6)     # shield gradient top
BOT = (0x1e, 0x5f, 0xd0)     # shield gradient bottom
WHITE = (255, 255, 255)
CHK = [(0.34, 0.545), (0.455, 0.665), (0.705, 0.40)]   # check-mark vertices (fractions)


def lerp(a, b, t):
    return a + (b - a) * t


def shield_hw(yf):
    """Half-width of the shield (as a fraction of the canvas) at vertical fraction yf."""
    top, mid, tip, wbody, r = 0.085, 0.52, 0.95, 0.40, 0.14
    if yf < top or yf > tip:
        return 0.0
    if yf <= mid:
        hw = wbody
        if yf < top + r:
            dy = (top + r) - yf
            hw = wbody - (r - math.sqrt(max(0.0, r * r - min(dy, r) ** 2)))
        return hw
    t = (yf - mid) / (tip - mid)
    return wbody * (1 - t) * (1 - 0.15 * t)


def in_shield(xf, yf):
    hw = shield_hw(yf)
    return hw > 0 and abs(xf - 0.5) <= hw


def _dseg(px, py, ax, ay, bx, by):
    vx, vy, wx, wy = bx - ax, by - ay, px - ax, py - ay
    ln = vx * vx + vy * vy
    t = 0.0 if ln == 0 else max(0.0, min(1.0, (wx * vx + wy * vy) / ln))
    return math.hypot(ax + t * vx - px, ay + t * vy - py)


def in_check(xf, yf):
    d = min(_dseg(xf, yf, *CHK[0], *CHK[1]), _dseg(xf, yf, *CHK[1], *CHK[2]))
    return d <= 0.062


def render(size, s=5):
    raw = bytearray()
    for j in range(size):
        raw.append(0)                                   # PNG filter byte (none) per scanline
        for i in range(size):
            cov_s = cov_c = 0
            for sj in range(s):
                for si in range(s):
                    xf = (i + (si + 0.5) / s) / size
                    yf = (j + (sj + 0.5) / s) / size
                    if not in_shield(xf, yf):
                        continue
                    if in_check(xf, yf):
                        cov_c += 1
                    else:
                        cov_s += 1
            n = s * s
            tot = cov_s + cov_c
            if tot == 0:
                raw += bytes((0, 0, 0, 0))
                continue
            yc = (j + 0.5) / size
            tcol = min(1.0, max(0.0, (yc - 0.1) / 0.8))
            sc = [lerp(TOP[k], BOT[k], tcol) for k in range(3)]
            rr = (sc[0] * cov_s + WHITE[0] * cov_c) / tot
            gg = (sc[1] * cov_s + WHITE[1] * cov_c) / tot
            bb = (sc[2] * cov_s + WHITE[2] * cov_c) / tot
            a = tot / n
            raw += bytes((int(rr + 0.5), int(gg + 0.5), int(bb + 0.5), int(a * 255 + 0.5)))
    return raw


def write_png(path, size, raw):
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data +
                struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff))
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)   # 8-bit RGBA, no interlace
    idat = zlib.compress(bytes(raw), 9)
    with open(path, "wb") as f:
        f.write(sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b""))


def main():
    os.makedirs(OUT, exist_ok=True)
    for sz in SIZES:
        p = os.path.join(OUT, "icon-%d.png" % sz)
        write_png(p, sz, render(sz, s=6 if sz <= 32 else 5))
        print("wrote", p)


if __name__ == "__main__":
    main()
