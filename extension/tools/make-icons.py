#!/usr/bin/env python3
"""Render the Scouter Browser Defense extension icons from icons/icon.svg.

The icon is the Scouter "scouter"/eyepiece glyph (see icons/icon.svg — the same mark as the agent
UI header). This renders it to transparent PNGs at the sizes the manifests reference, using whatever
SVG renderer is available. The committed PNGs are the source of truth; this just regenerates them.

    python3 tools/make-icons.py

Renderers tried, in order: rsvg-convert, cairosvg (Python), inkscape. If none is installed, it prints
a one-line browser-canvas fallback you can paste into any page's devtools (it preserves transparency).
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.dirname(HERE)
SVG = os.path.join(EXT, "icons", "icon.svg")
OUTDIR = os.path.join(EXT, "icons")
SIZES = [16, 32, 48, 128]


def via_rsvg(size, out):
    subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size), SVG, "-o", out], check=True)


def via_cairosvg(size, out):
    import cairosvg  # noqa: E401
    cairosvg.svg2png(url=SVG, write_to=out, output_width=size, output_height=size)


def via_inkscape(size, out):
    subprocess.run(["inkscape", SVG, "--export-type=png", "--export-filename=" + out,
                    "-w", str(size), "-h", str(size)], check=True)


def pick():
    if shutil.which("rsvg-convert"):
        return via_rsvg
    try:
        import cairosvg  # noqa: F401
        return via_cairosvg
    except Exception:  # noqa: BLE001
        pass
    if shutil.which("inkscape"):
        return via_inkscape
    return None


def main():
    render = pick()
    if render is None:
        print("No SVG renderer found (install librsvg's rsvg-convert, or `pip install cairosvg`, or "
              "inkscape).\nThe committed PNGs in icons/ are ready to use. To regenerate in a browser,\n"
              "open any page's devtools and run a canvas render of icons/icon.svg, saving each size.",
              file=sys.stderr)
        return 1
    for sz in SIZES:
        out = os.path.join(OUTDIR, "icon-%d.png" % sz)
        render(sz, out)
        print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
