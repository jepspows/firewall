"""
Firewall Desktop App — System tray wrapper for the Firewall server.

Architecture:
  The desktop app is a thin system-tray wrapper around the Firewall FastAPI server.
  It starts the server, shows a tray icon, and provides a menu for controlling it.

How it works:
  1. App launches → starts uvicorn in a daemon thread on 127.0.0.1:8787
  2. System tray icon appears (Mac menu bar / Windows notification area)
  3. Default browser opens to the Firewall dashboard
  4. Tray menu: Open Dashboard, Status, Start/Stop server, Quit
  5. Quit → graceful server shutdown → app exits

Packaging (PyInstaller):
  PyInstaller bundles the Python interpreter, all dependencies, and this script
  into a single executable. On Mac this becomes Firewall.app. On Windows, Firewall.exe.
  The bundled app is self-contained — no Python or pip needed by the user.

  Mac:     pyinstaller desktop/firewall-mac.spec  → dist/Firewall.app
  Windows: pyinstaller desktop/firewall-win.spec  → dist/Firewall.exe

Distribution:
  Mac:  .dmg disk image (hdiutil create) or .zip
  Win:  .exe installer (NSIS/Inno Setup) or standalone .exe
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — when bundled by PyInstaller, sys._MEIPASS is the temp extract dir
# ---------------------------------------------------------------------------

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        # Running as bundled app
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


BASE_DIR = _base_dir()
SERVER_MODULE = "firewall.server"
HOST = os.environ.get("FIREWALL_HOST", "127.0.0.1")
PORT = int(os.environ.get("FIREWALL_PORT", "8787"))
DASHBOARD_URL = f"http://{HOST}:{PORT}/dashboard"

logger = logging.getLogger("firewall-app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

# ---------------------------------------------------------------------------
# Server process management
# ---------------------------------------------------------------------------
# We run the server as a subprocess (not in-thread) so it gets proper signal
# handling and clean shutdown. This also avoids thread-safety issues with the
# async event loop.

_server_process: subprocess.Popen[bytes] | None = None
_lock = threading.Lock()


def server_is_running() -> bool:
    with _lock:
        return _server_process is not None and _server_process.poll() is None


def start_server() -> bool:
    """Start the Firewall server as a subprocess. Returns True if started."""
    global _server_process
    with _lock:
        if server_is_running():
            logger.info("Server already running")
            return False

        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            f"{SERVER_MODULE}:app",
            "--host", HOST,
            "--port", str(PORT),
            "--log-level", "warning",
            "--no-access-log",
        ]
        # On Windows, CREATE_NO_WINDOW prevents a console window from appearing
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

        _server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        logger.info(f"Server started (pid={_server_process.pid}) on {HOST}:{PORT}")
        return True


def stop_server() -> bool:
    """Gracefully stop the server. Returns True if it was running."""
    global _server_process
    with _lock:
        if _server_process is None or _server_process.poll() is not None:
            _server_process = None
            return False

        pid = _server_process.pid
        logger.info(f"Stopping server (pid={pid})...")
        try:
            if sys.platform == "win32":
                _server_process.terminate()
            else:
                _server_process.send_signal(signal.SIGTERM)
            _server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("Server didn't stop, force-killing...")
            _server_process.kill()
            _server_process.wait(timeout=3)
        except Exception:
            pass

        _server_process = None
        logger.info("Server stopped")
        return True


# ---------------------------------------------------------------------------
# Cross-platform tray icon
# We try pystray first; fall back to a headless mode if not available.
# ---------------------------------------------------------------------------

def _build_tray_menu(tray_icon):
    """Build the tray menu. Rebuilt each time the menu opens so status is live."""
    try:
        from pystray import Menu, MenuItem
    except ImportError:
        return None

    running = server_is_running()
    status_text = f"Server: {'ONLINE' if running else 'OFFLINE'}"

    def _open_dashboard(icon, item):
        webbrowser.open(DASHBOARD_URL)

    def _toggle_server(icon, item):
        if server_is_running():
            stop_server()
        else:
            start_server()
        # Rebuild menu on next click — pystray caches the menu, but
        # we rebuild each time by using a callable.

    def _quit_app(icon, item):
        stop_server()
        icon.stop()

    return Menu(
        MenuItem(status_text, None, enabled=False),
        Menu.SEPARATOR,
        MenuItem("Open Dashboard", _open_dashboard, default=True),
        MenuItem("Start Server" if not running else "Stop Server", _toggle_server),
        Menu.SEPARATOR,
        MenuItem(f"Firewall v0.2.0 — Port {PORT}", None, enabled=False),
        Menu.SEPARATOR,
        MenuItem("Quit", _quit_app),
    )


def _make_icon_image():
    """Generate a simple shield icon in-memory with Pillow.

    We draw a 64x64 shield shape programmatically so there are no
    external image files to bundle.
    """
    from PIL import Image, ImageDraw

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape
    shield_coords = [
        (32, 4),   # top center
        (56, 8),   # top right
        (56, 28),  # right mid
        (40, 52),  # bottom right
        (32, 60),  # bottom point
        (24, 52),  # bottom left
        (8, 28),   # left mid
        (8, 8),    # top left
    ]

    # Shield fill — dark with gradient feel
    draw.polygon(shield_coords, fill=(30, 30, 40, 255), outline=(100, 200, 255, 255))

    # Inner shield
    inner = [
        (32, 10),
        (50, 14),
        (50, 26),
        (38, 45),
        (32, 51),
        (26, 45),
        (14, 26),
        (14, 14),
    ]
    draw.polygon(inner, fill=(20, 60, 120, 255), outline=(100, 200, 255, 200))

    # "FW" text
    try:
        font = ImageFont.truetype("arial.ttf", 16)
    except Exception:
        font = ImageFont.load_default()
    draw.text((23, 22), "FW", fill=(255, 255, 255, 255), font=font)

    return img


def _run_tray():
    """Run the system tray loop. Blocks until quit."""
    try:
        import pystray
        from pystray import Menu, MenuItem
    except ImportError:
        logger.error(
            "pystray not installed. Install with: pip install pystray pillow\n"
            "Running in headless mode — the server will keep running until Ctrl+C."
        )
        _headless_loop()
        return

    icon_img = _make_icon_image()
    # Use a callable for the menu so it rebuilds each time
    icon = pystray.Icon(
        "firewall",
        icon_img,
        "Firewall — Prompt Injection Protection",
        menu=_build_tray_menu,
    )
    icon.run()


def _headless_loop():
    """Fallback: run headless with a simple prompt."""
    print(f"\n  Firewall Desktop v0.2.0")
    print(f"  Dashboard: {DASHBOARD_URL}")
    print(f"  Press Ctrl+C to stop\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_server()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Entry point — start server, launch tray, open dashboard."""
    logger.info("Firewall Desktop v0.2.0 starting...")

    # Add the project source to path so 'firewall.server' import works
    # when running from a dev install
    src_dir = BASE_DIR / "src"
    if src_dir.exists() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    # Start the server
    if not start_server():
        logger.warning("Could not start server")

    # Give the server a moment to boot before opening the browser
    time.sleep(1.5)

    # Open dashboard in default browser
    webbrowser.open(DASHBOARD_URL)

    # Run the tray icon — blocks until quit
    _run_tray()

    logger.info("Firewall Desktop exiting.")


if __name__ == "__main__":
    main()
