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

import asyncio
import logging
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

# ---------------------------------------------------------------------------
# Paths — when bundled by PyInstaller, sys._MEIPASS is the temp extract dir
# ---------------------------------------------------------------------------

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        # Running as bundled app
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


BASE_DIR = _base_dir()
HOST = os.environ.get("FIREWALL_HOST", "127.0.0.1")
PORT = int(os.environ.get("FIREWALL_PORT", "8787"))
DASHBOARD_URL = f"http://{HOST}:{PORT}/dashboard"

logger = logging.getLogger("firewall-app")

# Log to a file in the user's home directory (works even in GUI mode with no console)
_log_dir = Path(os.environ.get("FIREWALL_LOG_DIR", str(Path.home() / ".firewall")))
_log_dir.mkdir(parents=True, exist_ok=True)
_log_file = _log_dir / "firewall-desktop.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(str(_log_file)),
        logging.StreamHandler(sys.stderr),
    ],
)
logger.info(f"Firewall Desktop starting — log: {_log_file}")

# ---------------------------------------------------------------------------
# Server management — runs uvicorn in-process in a daemon thread
# ---------------------------------------------------------------------------
# We run uvicorn in the same process (not a subprocess) because:
#   - PyInstaller bundles don't have a standalone Python interpreter;
#     sys.executable is Firewall.exe, not python.
#   - In-process avoids subprocess overhead, portability issues, and
#     signal-handling complexity.
# The server runs in a daemon thread with its own event loop.

_server_thread: threading.Thread | None = None
_uvicorn_server: uvicorn.Server | None = None
_lock = threading.RLock()  # reentrant — server_is_running called inside locked blocks


def server_is_running() -> bool:
    with _lock:
        return _uvicorn_server is not None and _uvicorn_server.started


def start_server() -> bool:
    """Start the Firewall server in a daemon thread. Returns True if started."""
    global _server_thread, _uvicorn_server
    
    with _lock:
        if server_is_running():
            logger.info("Server already running")
            return False
    
    # Import outside the lock — may take time in PyInstaller bundles
    logger.info("Importing firewall.server...")
    try:
        from firewall.server import app as _firewall_app
    except Exception:
        logger.exception("Failed to import firewall.server")
        return False
    logger.info("firewall.server imported OK")
    
    logger.info("Creating uvicorn config...")
    try:
        config = uvicorn.Config(
            _firewall_app,
            host=HOST,
            port=PORT,
            log_level="warning",
            access_log=False,
        )
    except Exception:
        logger.exception("Failed to create uvicorn config")
        return False

    with _lock:
        _uvicorn_server = uvicorn.Server(config)

        def _run_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(_uvicorn_server.serve())
            except Exception:
                logger.exception("Server runtime error")
            finally:
                loop.close()
                logger.info("Server thread exiting")

        _server_thread = threading.Thread(target=_run_server, daemon=True)
        _server_thread.start()
    logger.info(f"Server thread started, binding to {HOST}:{PORT}")
    return True


def stop_server() -> bool:
    """Gracefully stop the server. Returns True if it was running."""
    global _server_thread, _uvicorn_server
    with _lock:
        if _uvicorn_server is None or not _uvicorn_server.started:
            _uvicorn_server = None
            _server_thread = None
            return False

        logger.info("Stopping server...")
        _uvicorn_server.should_exit = True
        # Give the server a moment to drain
        time.sleep(0.5)

        _uvicorn_server = None
        _server_thread = None
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
    from PIL import Image, ImageDraw, ImageFont

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
    """Run the system tray loop. Blocks until quit.
    
    Falls back to headless mode if pystray isn't installed or can't
    connect to a display (e.g., headless server, SSH session, CI).
    """
    try:
        import pystray
        from pystray import Menu, MenuItem
    except ImportError:
        logger.info("pystray not installed — running in headless mode")
        _headless_loop()
        return

    icon_img = _make_icon_image()
    icon = pystray.Icon(
        "firewall",
        icon_img,
        "Firewall — Prompt Injection Protection",
        menu=_build_tray_menu,
    )

    try:
        icon.run()
    except Exception as e:
        logger.warning(f"Tray icon failed ({e}) — falling back to headless mode")
        _headless_loop()


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
    logger.info("Starting server...")
    if not start_server():
        logger.warning("Could not start server")
    else:
        logger.info("Server start requested, waiting for boot...")

    # Give the server a moment to boot before opening the browser
    time.sleep(1.5)

    # Check if server actually came up
    if server_is_running():
        logger.info(f"Server is running on {HOST}:{PORT}")
    else:
        logger.error("Server failed to start!")
        # Keep going anyway — maybe it's just slow

    # Open dashboard in default browser
    logger.info("Opening dashboard...")
    webbrowser.open(DASHBOARD_URL)

    # Run the tray icon — blocks until quit
    logger.info("Starting tray icon...")
    _run_tray()

    logger.info("Firewall Desktop exiting.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.exception("Fatal error in main()")
        # Keep the process alive briefly so logs can be read
        import time
        time.sleep(2)
