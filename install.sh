#!/usr/bin/env bash
# ATPTmaster installer for Kali/Debian. Sets up the stdlib-only core, optionally
# exposes the `atpt` command, and REPORTS optional scanner availability. Nothing
# is installed silently: the optional pentest tools are added only with
# --with-tools (sudo apt + go install). Core needs no pip dependencies.
#
#   ./install.sh                 # core setup + tool availability report
#   ./install.sh --pipx          # also expose the `atpt` command via pipx
#   ./install.sh --with-tools     # also install the optional scanners (sudo)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
WITH_TOOLS=0; DO_PIPX=0
for a in "$@"; do
  case "$a" in
    --with-tools) WITH_TOOLS=1 ;;
    --pipx)       DO_PIPX=1 ;;
    -h|--help)    echo "usage: install.sh [--pipx] [--with-tools]"; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

echo "[*] ATPTmaster -> $here"
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 10)' \
  || { echo "need Python >= 3.10"; exit 1; }
mkdir -p "$here/var"
echo "[*] core is stdlib-only; no pip dependencies required."

# --- optionally expose the `atpt` command ----------------------------------
if [ "$DO_PIPX" = 1 ]; then
  if command -v pipx >/dev/null; then
    pipx install -e "$here" && echo "[*] 'atpt' installed via pipx"
  else
    echo "[!] pipx not found — install it first:  python3 -m pip install --user pipx"
  fi
else
  echo "[*] expose the 'atpt' command:  pipx install -e \"$here\"   (or just: python3 -m atpt ...)"
fi

# --- optional scanner availability (report; opt-in install) ----------------
echo "[*] optional tool availability:"
for t in nmap sqlmap jq aircrack-ng apktool subfinder naabu httpx nuclei ffuf prowler ollama; do
  if command -v "$t" >/dev/null 2>&1; then echo "    ok   $t"
  else echo "    MISS $t (the module needing it will no-op)"; fi
done

if [ "$WITH_TOOLS" = 1 ]; then
  echo "[*] installing apt scanners (sudo)…"
  sudo apt-get update -y \
    && sudo apt-get install -y nmap sqlmap jq aircrack-ng apktool golang-go || true
  if command -v go >/dev/null; then
    for g in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      github.com/ffuf/ffuf/v2@latest ; do
      echo "    go install $g"; go install "$g" || true
    done
    echo "[*] add \$HOME/go/bin to PATH so the go tools are found"
  fi
  echo "[*] cloud audit:  pipx install prowler    |    local LLM:  https://ollama.com"
else
  echo "[*] install the optional scanners:  ./install.sh --with-tools   (sudo apt + go install)"
fi

echo "[*] smoke test:  (cd \"$here\" && python3 -m atpt modules)"
echo "[*] launch console:  (cd \"$here\" && python3 -m atpt serve)   # http://127.0.0.1:8787"
