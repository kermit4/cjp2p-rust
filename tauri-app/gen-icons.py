#!/usr/bin/env python3
"""Generate minimal placeholder PNG icons for the Tauri build.
Run from tauri-app/src-tauri/:  python3 ../gen-icons.py
Replace icons/128x128.png with real artwork before shipping.
"""
import os, struct, zlib

def make_png(w, h):
    def chunk(tag, data):
        c = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", c)

    rows = []
    for y in range(h):
        row = bytearray([0])  # filter=None
        for x in range(w):
            # Dark navy background with a lighter square in the centre (RGBA)
            mx, my = w // 4, h // 4
            if mx <= x < w - mx and my <= y < h - my:
                row += bytearray([0x4A, 0x9E, 0xFF, 0xFF])  # blue accent
            else:
                row += bytearray([0x1A, 0x1A, 0x2E, 0xFF])  # dark navy
        rows.append(bytes(row))

    raw = b"".join(rows)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )

sizes = [
    (32,  32,  "icons/32x32.png"),
    (128, 128, "icons/128x128.png"),
    (256, 256, "icons/128x128@2x.png"),
]

os.makedirs("icons", exist_ok=True)
for w, h, path in sizes:
    with open(path, "wb") as f:
        f.write(make_png(w, h))
    print(f"  {path}")
