#!/usr/bin/env bash
# =============================================================================
# ATPTmaster :: recon_runner.sh  — Nebula-style CLI wrapper (Phase 1 / Recon)
#
# Chains: subfinder -> naabu -> nmap(-sV) -> httpx -> ffuf
# Emits : JSONL to stdout (one native tool record per line, tagged _tool /
#         _engagement_id). Logs to stderr. N8N captures stdout for normalizing.
#
# SAFETY: every target/host is checked against scope.json (in_scope_domains,
#         in_scope_cidrs, out_of_scope) BEFORE any tool touches it. Out-of-scope
#         input is skipped and logged — never scanned. This enforcement lives at
#         the tool layer on purpose, so it holds even if N8N is bypassed.
# =============================================================================
set -uo pipefail

ENGAGEMENT=""; SCOPE_FILE=""; TOOLS="subfinder,naabu,httpx"
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
RATE="150"; CHECK_SCOPE=""
declare -a TARGETS=()

log(){ echo "[recon_runner] $*" >&2; }
die(){ log "FATAL: $*"; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --engagement)  ENGAGEMENT="$2"; shift 2;;
    --scope)       SCOPE_FILE="$2"; shift 2;;
    --tools)       TOOLS="$2"; shift 2;;
    --target)      TARGETS+=("$2"); shift 2;;
    --wordlist)    WORDLIST="$2"; shift 2;;
    --rate)        RATE="$2"; shift 2;;
    --check-scope) CHECK_SCOPE="$2"; shift 2;;
    *) die "unknown arg: $1";;
  esac
done

command -v jq      >/dev/null || die "jq not found"
command -v python3 >/dev/null || die "python3 not found"
[[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]] || die "scope file missing: $SCOPE_FILE"

# --- scope oracle: exit 0 = in scope, 1 = out of scope --------------------
in_scope(){
  python3 - "$SCOPE_FILE" "$1" <<'PY'
import sys, json, re, ipaddress
scope = json.load(open(sys.argv[1]))
raw   = sys.argv[2].strip().lower()
host  = re.sub(r'^\w+://', '', raw).split('/')[0].split(':')[0]
def dom(h):
    for d in scope.get('in_scope_domains', []):
        d = d.lower().lstrip('.')
        if h == d or h.endswith('.' + d): return True
    return False
def cidr(h):
    try: ip = ipaddress.ip_address(h)
    except ValueError: return False
    for c in scope.get('in_scope_cidrs', []):
        try:
            if ip in ipaddress.ip_network(c, strict=False): return True
        except ValueError: pass
    return False
for d in scope.get('out_of_scope', []):        # explicit deny always wins
    d = d.lower().lstrip('.')
    if host == d or host.endswith('.' + d): sys.exit(1)
sys.exit(0 if (dom(host) or cidr(host)) else 1)
PY
}

# --- scope-check mode (used by an optional N8N IF gate) -------------------
if [[ -n "$CHECK_SCOPE" ]]; then
  if in_scope "$CHECK_SCOPE"; then echo "IN_SCOPE"; exit 0; else echo "OUT_OF_SCOPE"; exit 1; fi
fi

[[ -n "$ENGAGEMENT" ]]   || die "--engagement required"
[[ ${#TARGETS[@]} -gt 0 ]] || die "no --target provided"

declare -a SAFE=()
for t in "${TARGETS[@]}"; do
  if in_scope "$t"; then SAFE+=("$t"); else log "SKIP out-of-scope target: $t"; fi
done
[[ ${#SAFE[@]} -gt 0 ]] || die "all targets out of scope; nothing to do"

has(){ [[ ",$TOOLS," == *",$1,"* ]]; }
bin(){ command -v "$1" >/dev/null 2>&1; }
emit(){ jq -c --arg tool "$1" --arg eng "$ENGAGEMENT" \
          '. + {_tool:$tool,_engagement_id:$eng}' 2>/dev/null || true; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
HOSTS="$WORK/hosts.txt"; PORTS="$WORK/ports.txt"; LIVE="$WORK/live.txt"
: > "$HOSTS"; : > "$PORTS"; : > "$LIVE"
for t in "${SAFE[@]}"; do echo "$t" >> "$HOSTS"; done

# ---------- subfinder : passive subdomains --------------------------------
if has subfinder && bin subfinder; then
  for t in "${SAFE[@]}"; do
    [[ "$t" =~ ^[0-9.]+(/[0-9]+)?$ ]] && continue    # skip IPs/CIDRs
    subfinder -silent -json -d "$t" 2>>"$WORK/err.log" | while IFS= read -r ln; do
      printf '%s\n' "$ln" | emit subfinder
      h=$(printf '%s' "$ln" | jq -r '.host // empty'); [[ -n "$h" ]] && echo "$h" >> "$HOSTS"
    done
  done
fi
sort -u "$HOSTS" -o "$HOSTS"

# ---------- naabu : port scan (scope re-checked per host) -----------------
if has naabu && bin naabu; then
  SCOPED="$WORK/scoped.txt"; : > "$SCOPED"
  while IFS= read -r h; do in_scope "$h" && echo "$h" >> "$SCOPED"; done < "$HOSTS"
  if [[ -s "$SCOPED" ]]; then
    naabu -silent -json -rate "$RATE" -list "$SCOPED" 2>>"$WORK/err.log" | while IFS= read -r ln; do
      printf '%s\n' "$ln" | emit naabu
      printf '%s' "$ln" | jq -r '"\(.host // .ip):\(.port)"' >> "$PORTS"
    done
  fi
fi

# ---------- nmap : service/version detection -------------------------------
if has nmap && bin nmap; then
  if [[ -s "$PORTS" ]]; then
    # ports already discovered (e.g. by naabu) -> version-scan exactly those
    awk -F: '{h[$1]=h[$1]","$2} END{for(k in h){p=h[k];sub(/^,/,"",p);print k" "p}}' "$PORTS" \
    | while read -r host ports; do
        in_scope "$host" || { log "SKIP nmap out-of-scope: $host"; continue; }
        nmap -sV -Pn -p "$ports" -oX - "$host" 2>>"$WORK/err.log" \
          | python3 "$SELF_DIR/nmap2json.py" 2>>"$WORK/err.log" \
          | while IFS= read -r ln; do printf '%s\n' "$ln" | emit nmap; done
      done
  else
    # no prior port discovery (e.g. naabu absent) -> nmap the scoped hosts directly,
    # and feed the open ports forward so httpx/ffuf can probe them.
    while IFS= read -r host; do
      [[ -n "$host" ]] || continue
      in_scope "$host" || { log "SKIP nmap out-of-scope: $host"; continue; }
      nmap -sV -Pn --top-ports "${NMAP_TOP_PORTS:-1000}" -oX - "$host" 2>>"$WORK/err.log" \
        | python3 "$SELF_DIR/nmap2json.py" 2>>"$WORK/err.log" \
        | while IFS= read -r ln; do
            printf '%s\n' "$ln" | emit nmap
            printf '%s' "$ln" | jq -r '"\(.host // .ip):\(.port)"' >> "$PORTS"
          done
    done < "$HOSTS"
  fi
fi

# ---------- httpx : live web probe (status/title/tech/tls) ----------------
if has httpx && bin httpx; then
  IN="$WORK/httpx_in.txt"
  if [[ -s "$PORTS" ]]; then cp "$PORTS" "$IN"; else cp "$HOSTS" "$IN"; fi
  if [[ -s "$IN" ]]; then
    httpx -silent -json -rate-limit "$RATE" -title -tech-detect -status-code -list "$IN" \
      2>>"$WORK/err.log" | while IFS= read -r ln; do
        printf '%s\n' "$ln" | emit httpx
        u=$(printf '%s' "$ln" | jq -r '.url // empty'); [[ -n "$u" ]] && echo "$u" >> "$LIVE"
      done
  fi
fi

# ---------- ffuf : content discovery (the "DirBuster" role) ---------------
if has ffuf && bin ffuf && [[ -f "$WORDLIST" && -s "$LIVE" ]]; then
  while IFS= read -r u; do
    in_scope "$u" || { log "SKIP ffuf out-of-scope: $u"; continue; }
    ffuf -s -rate "$RATE" -w "$WORDLIST" -u "${u%/}/FUZZ" \
         -mc 200,204,301,302,307,401,403 -of json -o "$WORK/ffuf.json" \
         >/dev/null 2>>"$WORK/err.log" || { log "ffuf failed: $u"; continue; }
    jq -c --arg base "$u" \
      '.results[]? | {url:.url,status:.status,length:.length,words:.words,input:(.input.FUZZ // .input),base:$base}' \
      "$WORK/ffuf.json" 2>/dev/null | while IFS= read -r ln; do printf '%s\n' "$ln" | emit ffuf; done
  done < "$LIVE"
fi

log "recon complete :: engagement=$ENGAGEMENT tools=$TOOLS targets=${SAFE[*]}"
