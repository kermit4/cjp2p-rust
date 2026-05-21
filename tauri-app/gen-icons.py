#!/usr/bin/env python3
"""Generate all icon PNGs from SVG sources.  Run from anywhere."""
import subprocess, shutil, pathlib

here   = pathlib.Path(__file__).resolve().parent      # tauri-app/
root   = here.parent                                   # repo root
master = here / "icons" / "cjp2p_icon.svg"
fg     = here / "icons" / "cjp2p_fg.svg"
icons  = here / "src-tauri" / "icons"
res    = here / "src-tauri" / "gen" / "android" / "app" / "src" / "main" / "res"

def rsvg(svg, w, h, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rsvg-convert", "-w", str(w), "-h", str(h), "-o", str(out), str(svg)], check=True)

# Tauri desktop icons
rsvg(master, 32,  32,  icons / "32x32.png")
rsvg(master, 128, 128, icons / "128x128.png")
rsvg(master, 256, 256, icons / "128x128@2x.png")

# Web favicon — embedded by include_bytes!("favicon.png") in src/main.rs
rsvg(master, 32, 32, root / "src" / "favicon.png")

# Android launcher icons
for density, px in [("mdpi",48),("hdpi",72),("xhdpi",96),("xxhdpi",144),("xxxhdpi",192)]:
    p = res / f"mipmap-{density}" / "ic_launcher.png"
    rsvg(master, px, px, p)
    shutil.copy(p, p.parent / "ic_launcher_round.png")

# Android adaptive icon foreground (108dp canvas, bars within 72dp safe zone)
for density, px in [("mdpi",108),("hdpi",162),("xhdpi",216),("xxhdpi",324),("xxxhdpi",432)]:
    rsvg(fg, px, px, res / f"mipmap-{density}" / "ic_launcher_foreground.png")

print("icons generated")
