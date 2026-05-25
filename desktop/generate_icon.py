"""
Generate a proper Firewall app icon as a 1024x1024 PNG.
Run this once to produce desktop/icon.png, which is used by PyInstaller.
"""

from PIL import Image, ImageDraw, ImageFont


def create_icon(size: int = 1024, output: str = "desktop/icon.png"):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    m = size  # shorthand

    # Outer shield
    outer = [
        (m * 0.50, m * 0.08),   # top
        (m * 0.88, m * 0.14),   # top-right
        (m * 0.88, m * 0.42),   # mid-right
        (m * 0.62, m * 0.78),   # bottom-right
        (m * 0.50, m * 0.90),   # point
        (m * 0.38, m * 0.78),   # bottom-left
        (m * 0.12, m * 0.42),   # mid-left
        (m * 0.12, m * 0.14),   # top-left
    ]
    draw.polygon(outer, fill=(22, 24, 35, 255), outline=(80, 180, 255, 255), width=int(m * 0.02))

    # Inner shield (highlight)
    inner = [
        (m * 0.50, m * 0.16),
        (m * 0.78, m * 0.22),
        (m * 0.78, m * 0.40),
        (m * 0.58, m * 0.70),
        (m * 0.50, m * 0.78),
        (m * 0.42, m * 0.70),
        (m * 0.22, m * 0.40),
        (m * 0.22, m * 0.22),
    ]
    draw.polygon(inner, fill=(18, 55, 120, 255), outline=(80, 180, 255, 180), width=int(m * 0.01))

    # Center lock icon (simple)
    lock_cx = m * 0.50
    lock_cy = m * 0.42
    lock_w = m * 0.20
    lock_h = m * 0.22

    # Lock body
    body = [
        (lock_cx - lock_w, lock_cy - lock_h * 0.1),
        (lock_cx + lock_w, lock_cy - lock_h * 0.1),
        (lock_cx + lock_w, lock_cy + lock_h * 0.8),
        (lock_cx - lock_w, lock_cy + lock_h * 0.8),
    ]
    draw.rounded_rectangle(
        (body[0][0], body[0][1], body[2][0], body[2][1]),
        radius=int(m * 0.03),
        fill=(255, 255, 255, 255),
    )

    # Lock shackle
    shackle_top = lock_cy - lock_h * 0.6
    shackle_box = [
        lock_cx - lock_w * 0.6,
        shackle_top,
        lock_cx + lock_w * 0.6,
        lock_cy - lock_h * 0.1,
    ]
    draw.arc(
        shackle_box,
        start=180,
        end=0,
        fill=(255, 255, 255, 255),
        width=int(m * 0.04),
    )

    # Keyhole
    hole_r = m * 0.025
    hole_cx = lock_cx
    hole_cy = lock_cy + lock_h * 0.15
    draw.ellipse(
        [hole_cx - hole_r, hole_cy - hole_r * 1.3, hole_cx + hole_r, hole_cy + hole_r * 1.3],
        fill=(18, 55, 120, 255),
    )
    draw.rectangle(
        [hole_cx - hole_r * 0.4, hole_cy, hole_cx + hole_r * 0.4, hole_cy + lock_h * 0.3],
        fill=(18, 55, 120, 255),
    )

    # Glow ring around inner shield (subtle)
    for i in range(3):
        alpha = 40 - i * 12
        draw.polygon(inner, outline=(80, 180, 255, max(alpha, 5)), width=int(m * (0.03 + i * 0.02)))

    # Generate smaller versions for different platforms
    sizes = {
        "icon.png": size,
        "icon_256.png": 256,
        "icon_64.png": 64,
        "icon_32.png": 32,
        "icon_16.png": 16,
    }

    for fname, s in sizes.items():
        if s == size:
            resized = img
        else:
            resized = img.resize((s, s), Image.LANCZOS)
        resized.save(output.replace("icon.png", fname), "PNG")
        print(f"  ✓ {fname} ({s}x{s})")

    # Also save .ico for Windows (multi-size)
    ico_img = img.resize((256, 256), Image.LANCZOS)
    ico_path = output.replace("icon.png", "icon.ico")
    ico_img.save(ico_path, "ICO", sizes=[(256, 256), (64, 64), (48, 48), (32, 32), (16, 16)])
    print(f"  ✓ icon.ico (multi-size)")

    # .icns for Mac placeholder
    icns_img = img.resize((256, 256), Image.LANCZOS)
    icns_path = output.replace("icon.png", "icon.icns")
    # Pillow doesn't write .icns natively, but we save a reference PNG
    # Real .icns conversion happens in the Mac build script
    icns_img.save(icns_path.replace(".icns", "_pre_icns.png"), "PNG")
    print(f"  ✓ icon_pre_icns.png (convert to .icns for Mac distribution)")

    print(f"\nIcon set generated in desktop/")


if __name__ == "__main__":
    create_icon()
