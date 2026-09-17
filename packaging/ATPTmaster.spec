# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the ATPTmaster desktop app.

Build from the repo root:  pyinstaller packaging/ATPTmaster.spec
See packaging/README.md for the full flow (packaging/build.sh wraps it).

Bundles the code plus modules/ and atpt/assets/ as data. At first run the app
seeds those into a writable per-user data home (see atpt/desktop.prepare_home),
so the read-only bundle never has to be written to.

pywebview is bundled only when it is importable in the build environment
(macOS, where it wraps the native WKWebView). On Linux it is intentionally left
out — the frozen app falls back to a chromeless browser window instead of
bundling WebKitGTK, which is not portable.
"""
import os
import sys

repo_root = os.path.dirname(SPECPATH)  # noqa: F821 (SPECPATH injected by PyInstaller)

datas = [
    (os.path.join(repo_root, "modules"), "modules"),
    (os.path.join(repo_root, "atpt", "assets"), "atpt/assets"),
]

hiddenimports = []
try:
    import webview  # noqa: F401
    hiddenimports += ["webview"]
except Exception:
    pass

block_cipher = None

a = Analysis(
    [os.path.join(repo_root, "packaging", "desktop_main.py")],
    pathex=[repo_root],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

_icon = None
if sys.platform == "darwin":
    _icns = os.path.join(repo_root, "packaging", "ATPTmaster.icns")
    _icon = _icns if os.path.exists(_icns) else None

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ATPTmaster",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # windowed app — no terminal
    disable_windowed_traceback=False,
    icon=_icon,
)

if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="ATPTmaster.app",
        icon=_icon,
        bundle_identifier="com.avitwil.atptmaster",
        info_plist={"NSHighResolutionCapable": True},
    )
