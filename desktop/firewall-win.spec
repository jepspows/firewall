# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Firewall Desktop — Windows.

Builds a standalone Firewall.exe.
The .exe contains the Python interpreter, all dependencies, and the
Firewall server — no Python or pip needed on the target machine.

Output: dist/Firewall.exe

Usage:
  pip install pyinstaller
  pyinstaller desktop/firewall-win.spec --clean
"""

from pathlib import Path

# -- Paths ------------------------------------------------------------
ROOT = Path(".").resolve()
SRC = ROOT / "src"
DESKTOP = ROOT / "desktop"
ICON = DESKTOP / "icon.ico"

# -- Collect Firewall package data ------------------------------------
added_files = []

rules_dir = ROOT / "rules"
if rules_dir.exists():
    added_files.append((str(rules_dir), "rules"))

# Include dashboard.html so firewall.server can find it at module load
dashboard_html = SRC / "firewall" / "dashboard.html"
if dashboard_html.exists():
    added_files.append((str(dashboard_html), "firewall"))

docs_dir = ROOT / "docs"
if docs_dir.exists():
    added_files.append((str(docs_dir), "docs"))

# -- Build ------------------------------------------------------------
app_name = "Firewall"

a = Analysis(
    [str(DESKTOP / "app.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        # Firewall internals
        "firewall",
        "firewall.server",
        "firewall.engine",
        "firewall.classifier",
        "firewall.ml_classifier",
        "firewall.models",
        "firewall.rulesets",
        "firewall.prometheus_metrics",
        "firewall.redis_stats",
        "firewall.websocket_handler",
        # FastAPI / Starlette internals
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan.on",
        "fastapi",
        "starlette",
        "anyio",
        # ML deps
        "sklearn",
        "sklearn.feature_extraction.text",
        "sklearn.ensemble._forest",
        "sklearn.tree",
        "joblib",
        # System tray
        "pystray",
        "PIL",
        "PIL.Image",
        "PIL.ImageDraw",
        "PIL.ImageFont",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "test",
        "unittest",
        "pytest",
        "setuptools",
        "pip",
        "wheel",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

# Collect all uvicorn submodules
from PyInstaller.utils.hooks import collect_submodules
uvicorn_hidden = collect_submodules("uvicorn")
a.hiddenimports.extend(uvicorn_hidden)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=app_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # No terminal window — system tray app
    icon=str(ICON) if ICON.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name=app_name,
)
