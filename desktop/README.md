# Firewall Desktop App

Standalone desktop application for [Firewall](https://addfirewall.com) — the prompt injection firewall for AI agents.

Runs as a system tray app (Mac menu bar / Windows notification area). Starts the Firewall server in the background and opens the dashboard in your browser. No terminal needed.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    Firewall Desktop App                   │
│                                                          │
│  ┌──────────────┐    ┌─────────────────────┐             │
│  │ System Tray  │    │  Firewall Server     │             │
│  │   Menu Bar   │←──→│  localhost:8787      │             │
│  │              │    │                      │             │
│  │ • Dashboard  │    │  FastAPI + uvicorn   │             │
│  │ • Start/Stop │    │  4-layer detection   │             │
│  │ • Quit       │    │  ML classifier       │             │
│  └──────────────┘    └───────────────────────┘             │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

1. **App launches** → spawns uvicorn as a subprocess running the Firewall server on `127.0.0.1:8787`
2. **System tray icon** appears (shield icon with lock)
3. **Browser opens** to `http://127.0.0.1:8787/dashboard`
4. **Control via tray menu**: open dashboard, start/stop the server, quit
5. **On quit** → graceful shutdown: SIGTERM to server, wait, force-kill if needed

## Building

### Prerequisites

```bash
pip install pyinstaller pystray pillow
```

### Windows → Firewall.exe

```bash
# From the firewall repo root:
python desktop/build.py windows
# Output: dist/Firewall/Firewall.exe
```

This creates a standalone .exe (~80-120 MB, includes full Python + all ML deps). No Python required on the target machine. Distribute the `dist/Firewall/` folder or wrap it in an NSIS/Inno Setup installer.

### macOS → Firewall.app

```bash
# Must run on a Mac (needs iconutil for .icns)
python desktop/build.py mac
# Output: dist/Firewall.app
```

Creates a `.app` bundle (~100-150 MB). Runs as a **menu bar app** — no Dock icon, just the shield in the menu bar. Distribute as `.dmg`:

```bash
hdiutil create -volname Firewall -srcfolder dist/Firewall.app \
  -ov -format UDZO dist/Firewall-0.2.0.dmg
```

### What Gets Bundled

PyInstaller bundles everything into the executable:

| Component | How it's bundled |
|-----------|-----------------|
| Python 3.11+ interpreter | Compiled into the binary |
| Firewall server (FastAPI) | Imported as a module |
| uvicorn ASGI server | Imported as a module |
| ML classifier (scikit-learn) | Imported with compiled C extensions |
| YAML rulesets (`rules/`) | Copied as data files |
| Dashboard HTML (`docs/`) | Copied as data files |
| System tray (pystray) | Imported as a module |
| App icon (.ico / .icns) | Embedded via PyInstaller metadata |

## Distribution Checklist

### macOS

- [ ] Build on a Mac with Python 3.11+
- [ ] Sign with Developer ID: `codesign --deep --force --verify --sign "Developer ID Application: ..." dist/Firewall.app`
- [ ] Notarize: `xcrun notarytool submit dist/Firewall-0.2.0.dmg --apple-id ... --team-id ... --wait`
- [ ] Staple ticket: `xcrun stapler staple dist/Firewall-0.2.0.dmg`

### Windows

- [ ] Build on Windows with Python 3.11+
- [ ] Code sign with Authenticode certificate (optional, avoids SmartScreen warnings)
- [ ] Create installer with NSIS/Inno Setup (optional, for Start Menu + uninstaller)

## Manual Packaging (without build.py)

```bash
# One-liner for Windows:
pip install -e . && pyinstaller desktop/firewall-win.spec --clean --noconfirm

# One-liner for Mac:
pip install -e . && pyinstaller desktop/firewall-mac.spec --clean --noconfirm
```

## Headless Mode

If `pystray` is not installed, the app falls back to headless mode — the server runs and the dashboard opens, but there's no tray icon. Ctrl+C to quit.
