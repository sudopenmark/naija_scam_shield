"""
scripts/gen_assets.py — Generate Placeholder Icon & Splash Assets
Author: Joshua Akadri
GitHub: sudopenmark

Generates a minimal shield icon (PNG + ICO) and splash screen
so the app launches without missing-file errors before real artwork
is added.

Requires: Pillow   (pip install Pillow)
"""

import sys
import struct
import zlib
from pathlib import Path

ASSETS_DIR = Path(__file__).parent.parent / "assets"
ASSETS_DIR.mkdir(exist_ok=True)


# ── Minimal PNG writer (no external deps fallback) ────────────────────────────

def _write_png(path: Path, width: int, height: int, pixels):
    """
    Write a tiny PNG from a flat list of (R,G,B) tuples.
    pixels must have width*height entries.
    """
    def chunk(name: bytes, data: bytes) -> bytes:
        c = name + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    raw = b""
    for y in range(height):
        raw += b"\x00"
        for x in range(width):
            r, g, b = pixels[y * width + x]
            raw += bytes([r, g, b])

    sig   = b"\x89PNG\r\n\x1a\n"
    ihdr  = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    idat  = chunk(b"IDAT", zlib.compress(raw))
    iend  = chunk(b"IEND", b"")

    path.write_bytes(sig + ihdr + idat + iend)


def _draw_shield_pixels(width: int, height: int) -> list:
    """
    Draw a simple shield silhouette for the given canvas size.
    Returns a flat list of (R,G,B) tuples.
    """
    bg    = (15,  17,  23)    # #0f1117
    shield_fill  = (30, 33, 48)  # #1e2130
    accent = (59, 130, 246)   # #3b82f6
    text_c = (241, 245, 249)  # #f1f5f9

    pixels = [bg] * (width * height)

    cx, cy = width // 2, height // 2
    sw = int(width * 0.55)
    sh = int(height * 0.65)

    for y in range(height):
        for x in range(width):
            dx = x - cx
            dy = y - cy

            # Shield body: rounded top + pointed bottom
            nx = dx / (sw / 2)
            ny = dy / (sh / 2)

            in_top    = abs(nx) <= 1 and ny <= 0 and nx*nx + ny*ny <= 1.05
            in_sides  = abs(nx) <= (1 - max(0, ny) * 0.3) and ny <= 0.6
            in_bottom = abs(nx) <= (1 - ny) * 0.65 and ny > 0 and ny <= 1.0

            if in_top or in_sides or in_bottom:
                # Border (2px)
                border = (
                    abs(abs(nx) - (1 - max(0, ny) * 0.3)) < 0.08 or
                    (ny > 0.55 and abs(nx) < 0.12)
                )
                pixels[y * width + x] = accent if border else shield_fill

    # Draw a white "check" in the centre
    check_size = max(2, width // 14)
    for i in range(-check_size, check_size * 2):
        for j in range(-check_size, check_size):
            if (i + j) % 3 == 0:
                continue
            px = cx + i - check_size // 2
            py = cy + j
            if 0 <= px < width and 0 <= py < height:
                if (i < check_size and j > check_size // 2 - i) or (i >= check_size):
                    pixels[py * width + px] = text_c

    return pixels


def gen_icon(size: int = 256) -> Path:
    path = ASSETS_DIR / "icon.png"
    pixels = _draw_shield_pixels(size, size)
    _write_png(path, size, size, pixels)
    print(f"  ✅ icon.png  ({size}×{size})")
    return path


def gen_splash(width: int = 600, height: int = 300) -> Path:
    path = ASSETS_DIR / "splash.png"
    bg    = (15,  17,  23)
    accent= (59, 130, 246)

    pixels = [bg] * (width * height)

    # Horizontal accent line
    for x in range(width):
        for t in range(3):
            if height // 2 + t < height:
                pixels[(height // 2 + t) * width + x] = accent

    # Small shield in centre
    sw, sh = 80, 80
    cx, cy = width // 2 - sw // 2, height // 2 - sh // 2
    shield = _draw_shield_pixels(sw, sh)
    for sy in range(sh):
        for sx in range(sw):
            px, py = cx + sx, cy - sh // 2 + sy
            if 0 <= px < width and 0 <= py < height:
                if shield[sy * sw + sx] != bg:
                    pixels[py * width + px] = shield[sy * sw + sx]

    _write_png(path, width, height, pixels)
    print(f"  ✅ splash.png ({width}×{height})")
    return path


def gen_ico(source_png: Path) -> Path:
    """
    Create a minimal .ico file from a PNG.
    Falls back gracefully if Pillow is available.
    """
    ico_path = ASSETS_DIR / "icon.ico"
    try:
        from PIL import Image
        img = Image.open(source_png).convert("RGBA")
        img.save(ico_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
        print(f"  ✅ icon.ico  (multi-resolution)")
    except ImportError:
        # Write a minimal ICO containing the 256×256 PNG as a single image
        # (not all tools support this, but PyInstaller does)
        png_data = source_png.read_bytes()
        # ICO header (1 image, PNG type)
        header = struct.pack("<HHH", 0, 1, 1)
        # Image directory entry for 256×256 (stored as 0 in ICO spec)
        entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png_data), 22)
        ico_path.write_bytes(header + entry + png_data)
        print(f"  ✅ icon.ico  (single-size, no Pillow)")
    return ico_path


if __name__ == "__main__":
    print("Generating Naija Scam Shield assets…")
    icon_png = gen_icon(256)
    gen_splash(600, 300)
    gen_ico(icon_png)
    print(f"\nAll assets saved to: {ASSETS_DIR}")
