# Packaging the ATPTmaster desktop app

Turns the web console into a **double-click desktop app**. The UI is the same
web console (`atpt/web.py`); the desktop app just starts it on a private
localhost port and opens it in its own window.

## Build

From the repo root:

```bash
pip install -e '.[build]'      # pyinstaller (+ pywebview on macOS)
packaging/build.sh
```

Outputs land in `dist/`:

| OS | Artifact | Window |
|----|----------|--------|
| Linux / Kali | `dist/ATPTmaster` (single binary) + `dist/ATPTmaster.desktop` | chromeless browser window (uses an installed Chromium/Chrome) |
| macOS | `dist/ATPTmaster.app` | native WKWebView window (pywebview) |

### Install the artifact

- **Linux:** copy the menu launcher so it shows up in your app grid:
  ```bash
  cp dist/ATPTmaster.desktop ~/.local/share/applications/
  ```
- **macOS:** drag `dist/ATPTmaster.app` into `/Applications`. Optional disk image:
  ```bash
  hdiutil create -volname ATPTmaster -srcfolder dist/ATPTmaster.app -ov dist/ATPTmaster.dmg
  ```

## How it works

`packaging/desktop_main.py` calls `atpt.desktop.launch()`, which:

1. Resolves a **writable data home** — `~/.local/share/ATPTmaster` (Linux) or
   `~/Library/Application Support/ATPTmaster` (macOS).
2. Seeds `modules/` and `atpt/assets/` into it from the bundle on first run
   (never overwriting your copies), so engagement state, uploads and reports
   persist across app updates.
3. Starts the console server on a free `127.0.0.1` port in a background thread.
4. Opens the window — native (pywebview) if available, otherwise a chromeless
   browser app-window. Closing the window shuts the server down.

## Why pywebview is bundled only on macOS

On macOS pywebview wraps the OS-native WKWebView — nothing extra to ship. On
Linux it needs system WebKitGTK + PyGObject, which don't bundle portably, so the
Linux build deliberately omits it and falls back to a chromeless browser window.
Either way the console is byte-identical.

## Windows

Not a supported target for the packaged app (Linux + macOS only). Windows users
can still run the console with `atpt --u`.
