#!/usr/bin/env bash
# curl-able bootstrap: clone (or update) ATPTmaster, then run its installer.
#   curl -fsSL https://raw.githubusercontent.com/avitwil/ATPTmaster/main/bootstrap.sh | bash
# Optional: pass a target dir and installer flags, e.g.
#   ... | bash -s -- atpt --with-tools
set -euo pipefail
REPO="https://github.com/avitwil/ATPTmaster.git"
DIR="${1:-atpt}"; shift || true
command -v git >/dev/null || { echo "git is required"; exit 1; }
if [ -d "$DIR/.git" ]; then
  echo "[*] updating existing checkout in $DIR"
  git -C "$DIR" pull --ff-only
else
  echo "[*] cloning $REPO -> $DIR"
  git clone "$REPO" "$DIR"
fi
cd "$DIR"
exec ./install.sh "$@"
