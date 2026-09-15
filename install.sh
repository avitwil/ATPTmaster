#!/usr/bin/env bash
# ATPTmaster core installer for Kali. Sets up the core; WARNS about missing
# recon tools but never auto-installs them. Run tool installs yourself.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
echo "[*] ATPTmaster core -> $here"
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
python3 -c 'import sys; assert sys.version_info>=(3,10)' || { echo "need Python >=3.10"; exit 1; }
mkdir -p "$here/var"
echo "[*] core is stdlib-only; no pip deps required."
echo "[*] optional: pipx install -e \"$here\"   # to expose the 'atpt' command"
echo "[*] recon tool availability:"
for t in jq subfinder naabu nmap httpx ffuf; do
  if command -v "$t" >/dev/null 2>&1; then echo "    ok   $t"; else echo "    MISS $t (recon modules that need it will no-op)"; fi
done
echo "[*] smoke test:  python3 -m atpt modules"
