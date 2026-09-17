#!/usr/bin/env bash
# Build the ATPTmaster desktop app into a double-click installable bundle.
#
#   Linux/Kali → dist/ATPTmaster              (single binary)
#                dist/ATPTmaster.desktop       (menu launcher, copy to
#                                               ~/.local/share/applications/)
#   macOS      → dist/ATPTmaster.app           (drag to /Applications)
#
# Requires the build extra:  pip install -e '.[build]'   (adds pyinstaller;
# on macOS also pywebview for the native window). Run from the repo root.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"       # repo root
cd "$here" || exit 1

command -v pyinstaller >/dev/null || {
  echo "error: pyinstaller not found — run:  pip install -e '.[build]'" >&2
  exit 1
}

OS="$(uname -s)"
echo "[*] building ATPTmaster desktop app for $OS"

# macOS: native window via pywebview + a proper .icns icon.
if [ "$OS" = "Darwin" ]; then
  python3 -c 'import webview' 2>/dev/null || \
    echo "[!] pywebview missing — the .app will fall back to a browser window. Install with: pip install '.[desktop]'"
  # Build an .icns from the PNG logo (sips + iconutil ship with macOS).
  logo="$here/atpt/assets/logo.png"
  if [ -f "$logo" ] && command -v iconutil >/dev/null; then
    iconset="$(mktemp -d)/ATPTmaster.iconset"; mkdir -p "$iconset"
    for s in 16 32 64 128 256 512; do
      sips -z $s $s     "$logo" --out "$iconset/icon_${s}x${s}.png"      >/dev/null 2>&1
      sips -z $((s*2)) $((s*2)) "$logo" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null 2>&1
    done
    iconutil -c icns "$iconset" -o "$here/packaging/ATPTmaster.icns" && \
      echo "[*] icon -> packaging/ATPTmaster.icns"
  fi
fi

echo "[*] running pyinstaller…"
pyinstaller --noconfirm --clean packaging/ATPTmaster.spec || exit 1

if [ "$OS" = "Darwin" ]; then
  echo "[✔] built dist/ATPTmaster.app — drag it into /Applications"
  echo "    optional dmg:  hdiutil create -volname ATPTmaster -srcfolder dist/ATPTmaster.app -ov dist/ATPTmaster.dmg"
else
  # Linux: emit a .desktop launcher pointing at the built binary + PNG icon.
  bin="$here/dist/ATPTmaster"
  icon="$here/atpt/assets/logo.png"
  cat > "$here/dist/ATPTmaster.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=ATPTmaster
Comment=Autonomous Pentest Framework
Exec=$bin
Icon=$icon
Terminal=false
Categories=Security;Network;
EOF
  chmod +x "$here/dist/ATPTmaster.desktop"
  echo "[✔] built dist/ATPTmaster (single binary)"
  echo "    install the menu entry:  cp dist/ATPTmaster.desktop ~/.local/share/applications/"
  echo "    (the binary opens the console in a chromeless browser window)"
fi
