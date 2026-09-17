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

# --- branding (cyan -> purple -> green, matching the site logo) -------------
COLOR=plain
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  case "${COLORTERM:-}" in truecolor|24bit) COLOR=true ;; *) COLOR=256 ;; esac
fi
RST=''; DIM=''; OK=''; PUR=''
if [ "$COLOR" != plain ]; then
  RST=$'\033[0m'; DIM=$'\033[38;5;245m'; OK=$'\033[38;5;82m'
  [ "$COLOR" = true ] && PUR=$'\033[38;2;138;79;255m' || PUR=$'\033[38;5;141m'
fi

# Interpolate cyan(0,229,255) -> purple(138,79,255) -> green(90,255,90) at t=0..1000.
_grad_rgb() {
  local t=$1 r g b u
  if [ "$t" -lt 500 ]; then u=$((t*2))
    r=$(( 0   + (138-0)  *u/1000 )); g=$(( 229 + (79-229) *u/1000 )); b=$(( 255 + (255-255)*u/1000 ))
  else u=$(( (t-500)*2 ))
    r=$(( 138 + (90-138) *u/1000 )); g=$(( 79  + (255-79) *u/1000 )); b=$(( 255 + (90-255) *u/1000 ))
  fi
  printf '%d;%d;%d' "$r" "$g" "$b"
}

# Paint stdin: horizontal gradient per char (truecolor), tri-segment (256), or plain.
_paint() {
  local WREF=34 line i ch col t n a b
  if [ "$COLOR" = plain ]; then cat; return; fi
  while IFS= read -r line; do
    if [ "$COLOR" = true ]; then
      i=0
      while [ $i -lt ${#line} ]; do
        ch=${line:$i:1}; col=$i; [ $col -ge $WREF ] && col=$((WREF-1))
        t=$(( col*1000/(WREF-1) ))
        printf '\033[38;2;%sm%s' "$(_grad_rgb $t)" "$ch"; i=$((i+1))
      done
      printf '\033[0m\n'
    else
      n=${#line}; a=$(( n/3 )); b=$(( 2*n/3 ))
      printf '\033[38;5;51m%s\033[38;5;141m%s\033[38;5;82m%s\033[0m\n' \
        "${line:0:$a}" "${line:$a:$((b-a))}" "${line:$b}"
    fi
  done
}

show_logo() {
  local img="$here/atpt/assets/clilogo.png"
  # Render the real logo if the terminal has an image tool; else painted ASCII.
  if [ -f "$img" ] && [ -t 1 ]; then
    command -v chafa  >/dev/null 2>&1 && { chafa --size=42x22 "$img" 2>/dev/null && return 0; }
    command -v viu    >/dev/null 2>&1 && { viu -h 22 "$img"    2>/dev/null && return 0; }
    command -v catimg >/dev/null 2>&1 && { catimg -w 44 "$img" 2>/dev/null && return 0; }
  fi
  _paint <<'BANNER'
        ___    _____ ____  _____
       / _ \  |_   _|  _ \|_   _|
      | |_| |   | | | |_) | | |
      |  _  |   | | |  __/  | |
      |_| |_|   |_| |_|     |_|
              m a s t e r
BANNER
  printf '%s        Autonomous Pentest Framework%s\n' "$DIM" "$RST"
  printf '%s                by Avi Twil%s\n' "$PUR" "$RST"
}

show_logo
echo
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
echo
show_logo
printf '%s  ✔ Installation complete — ATPT master is ready.%s\n\n' "$OK" "$RST"
