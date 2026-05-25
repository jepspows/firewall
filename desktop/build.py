#!/usr/bin/env python3
"""
Firewall Desktop — Build script.
Builds standalone apps for macOS and Windows using PyInstaller.

Prerequisites:
  pip install pyinstaller pystray pillow

Usage:
  python desktop/build.py mac      # → dist/Firewall.app
  python desktop/build.py windows  # → dist/Firewall.exe
  python desktop/build.py all      # → both
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DESKTOP = ROOT / "desktop"
DIST = ROOT / "dist"
BUILD = ROOT / "build"


def run(cmd: list[str], **kwargs) -> None:
    print(f"  → {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=ROOT, **kwargs)


def check_deps():
    """Ensure build dependencies are installed."""
    print("Checking build dependencies...")
    try:
        import PyInstaller  # noqa: F401
        import pystray      # noqa: F401
        import PIL           # noqa: F401
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install with: pip install pyinstaller pystray pillow")
        sys.exit(1)
    print("  ✓ All dependencies present\n")


def ensure_icon():
    """Generate icons if they don't exist."""
    icon_png = DESKTOP / "icon.png"
    icon_ico = DESKTOP / "icon.ico"
    if not icon_png.exists() or not icon_ico.exists():
        print("Generating icons...")
        run([sys.executable, str(DESKTOP / "generate_icon.py")])
    else:
        print(f"Icons already exist: {icon_png}, {icon_ico}")


def clean():
    """Remove previous build artifacts."""
    for d in [DIST, BUILD]:
        if d.exists():
            print(f"Cleaning {d}...")
            shutil.rmtree(d)
    for spec in ROOT.glob("*.spec"):
        if spec.name not in ("firewall-mac.spec", "firewall-win.spec"):
            spec.unlink()


def build_mac():
    """Build macOS .app bundle."""
    print("=" * 60)
    print("Building Firewall.app for macOS")
    print("=" * 60)

    icon_icns = DESKTOP / "icon.icns"

    # macOS needs .icns format. Convert from PNG if needed.
    if not icon_icns.exists():
        pre = DESKTOP / "icon_pre_icns.png"
        if pre.exists():
            print("Converting icon to .icns format...")
            # Create a minimal .icns using sips (macOS built-in)
            os.system(
                f'mkdir -p /tmp/firewall_icon.iconset && '
                f'sips -z 16 16   {pre} --out /tmp/firewall_icon.iconset/icon_16x16.png && '
                f'sips -z 32 32   {pre} --out /tmp/firewall_icon.iconset/icon_32x32.png && '
                f'sips -z 128 128 {pre} --out /tmp/firewall_icon.iconset/icon_128x128.png && '
                f'sips -z 256 256 {pre} --out /tmp/firewall_icon.iconset/icon_256x256.png && '
                f'sips -z 512 512 {pre} --out /tmp/firewall_icon.iconset/icon_512x512.png && '
                f'iconutil -c icns /tmp/firewall_icon.iconset -o {icon_icns} && '
                f'rm -rf /tmp/firewall_icon.iconset'
            )
        else:
            print("⚠  No .icns icon found. The .app will have a default icon.")
            print("   Generate with: python desktop/generate_icon.py then run on a Mac for .icns")

    # Run PyInstaller
    # Install Firewall in dev mode so the server module is importable
    run([sys.executable, "-m", "pip", "install", "-e", "."])

    run([
        sys.executable, "-m", "PyInstaller",
        str(DESKTOP / "firewall-mac.spec"),
        "--clean",
        "--noconfirm",
    ])

    app_path = DIST / "Firewall.app"
    if app_path.exists():
        size = sum(f.stat().st_size for f in app_path.rglob("*") if f.is_file())
        size_mb = size / (1024 * 1024)
        print(f"\n✓ Firewall.app built: {app_path}")
        print(f"  Size: ~{size_mb:.0f} MB")
        print(f"\n  To distribute, create a DMG:")
        print(f"    hdiutil create -volname Firewall -srcfolder {app_path} "
              f"-ov -format UDZO dist/Firewall-0.2.0.dmg")
        print(f"\n  To sign for distribution:")
        print(f"    codesign --deep --force --verify --verbose "
              f'--sign "Developer ID Application: ..." {app_path}')
    else:
        print("✗ Build failed — no .app found")
        sys.exit(1)


def build_windows():
    """Build Windows .exe."""
    print("=" * 60)
    print("Building Firewall.exe for Windows")
    print("=" * 60)

    # Install Firewall in dev mode
    run([sys.executable, "-m", "pip", "install", "-e", "."])

    # Run PyInstaller
    run([
        sys.executable, "-m", "PyInstaller",
        str(DESKTOP / "firewall-win.spec"),
        "--clean",
        "--noconfirm",
    ])

    exe_path = DIST / "Firewall.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n✓ Firewall.exe built: {exe_path}")
        print(f"  Size: ~{size_mb:.0f} MB")

        print(f"\n  To create an installer with NSIS:")
        print(f"    Create a .nsi script pointing to dist/Firewall/")
        print(f"    Or just zip the dist/Firewall/ folder for portable distribution")
    else:
        # The EXE might be inside the COLLECT dir
        exe_in_dir = DIST / "Firewall" / "Firewall.exe"
        if exe_in_dir.exists():
            size_mb = exe_in_dir.stat().st_size / (1024 * 1024)
            print(f"\n✓ Firewall.exe built: {exe_in_dir}")
            print(f"  Size: ~{size_mb:.0f} MB")
        else:
            print("✗ Build failed — no .exe found")
            sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: python desktop/build.py [mac|windows|all]")
        sys.exit(1)

    target = sys.argv[1].lower()

    if target == "all":
        check_deps()
        ensure_icon()
        build_windows()
        print("\n" + "=" * 60)
        print("To build for Mac, run this script on a macOS machine:")
        print("  python desktop/build.py mac")
    elif target == "mac":
        if sys.platform != "darwin":
            print("⚠  Building for macOS requires running on a macOS machine.")
            print("   (iconutil and .icns generation need macOS)")
            yn = input("Continue anyway? [y/N] ").strip().lower()
            if yn != "y":
                sys.exit(0)
        check_deps()
        ensure_icon()
        build_mac()
    elif target == "windows":
        check_deps()
        ensure_icon()
        build_windows()
    else:
        print(f"Unknown target: {target}")
        print("Usage: python desktop/build.py [mac|windows|all]")
        sys.exit(1)


if __name__ == "__main__":
    main()
