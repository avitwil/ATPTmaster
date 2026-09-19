#!/usr/bin/env bash
# curl-able bootstrap: install ATPTmaster from the latest STABLE release, then run
# its installer. A stable release is a git tag vMAJOR.MINOR.PATCH; pre-release /
# beta tags (e.g. v1.2.0-beta.1) are ignored.
#   curl -fsSL https://raw.githubusercontent.com/avitwil/ATPTmaster/main/bootstrap.sh | bash
# Optional: pass a target dir and installer flags, e.g.
#   ... | bash -s -- atpt --with-tools
set -euo pipefail
REPO="https://github.com/avitwil/ATPTmaster.git"
DIR="${1:-atpt}"; shift || true
command -v git >/dev/null || { echo "git is required"; exit 1; }

# Latest stable release tag on the remote (highest vX.Y.Z; suffixed pre-releases skipped).
latest_stable_tag() {
  git ls-remote --tags --refs "$REPO" 'v*' 2>/dev/null \
    | awk -F/ '{print $NF}' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -V | tail -n1
}
TAG="$(latest_stable_tag || true)"

if [ -d "$DIR/.git" ]; then
  echo "[*] updating existing checkout in $DIR"
  git -C "$DIR" fetch --tags --quiet origin || true
  # keep user data (gitignored var/ & toolbox/); back up any stray local edits
  git -C "$DIR" stash push --include-untracked --message "bootstrap pre-update backup" >/dev/null 2>&1 || true
  if [ -n "$TAG" ]; then
    echo "[*] installing latest stable release $TAG"
    git -C "$DIR" reset --hard "$TAG"
  else
    echo "[!] no stable release found; staying on the current checkout"
  fi
else
  if [ -n "$TAG" ]; then
    echo "[*] cloning $REPO @ $TAG (latest stable release) -> $DIR"
    git clone --branch "$TAG" "$REPO" "$DIR"
  else
    echo "[!] no stable release published yet; cloning main -> $DIR"
    git clone "$REPO" "$DIR"
  fi
fi
cd "$DIR"
exec ./install.sh "$@"
