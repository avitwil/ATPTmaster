"""ScopeGuard: the authoritative pre-execution gate. Deterministic first — the
target of every command must be in scope (fail-closed), the binary must be
allow-listed, and no write/egress flag may be present. An optional judge_fn (an
LLM) may ADD a block, never remove one.

session_scope_ok vets a command run INSIDE a foothold session: all local activity
is allowed; only an outbound connection (ssh/curl/nc/…) to an OUT-OF-SCOPE host is
blocked (a pivot to an unauthorized machine). On a single-host engagement it never
fires."""
from __future__ import annotations
import re
from dataclasses import dataclass

from atpt.scope import in_scope

from .targets import extract_targets

_EGRESS = frozenset({"ssh", "scp", "sftp", "curl", "wget", "nc", "ncat", "netcat",
                     "telnet", "ftp", "tftp", "rsync", "socat"})
_LOCAL = frozenset({"127.0.0.1", "localhost", "0.0.0.0", "::1", ""})
_SUBSPLIT = re.compile(r"[;&|\n`]+|\$\(")
_SKIP_PROG = frozenset({"sudo", "-n", "command", "exec", "nohup", "time", "env", "sh", "-c", "bash"})


def session_scope_ok(cmd: str, scope: dict) -> tuple[bool, str]:
    """Allow local commands; block only a network tool dialing an out-of-scope host."""
    for sub in _SUBSPLIT.split(cmd or ""):
        toks = sub.split()
        i = 0
        while i < len(toks) and ("=" in toks[i] or toks[i] in _SKIP_PROG):
            i += 1
        if i >= len(toks):
            continue
        prog = toks[i].split("/")[-1]
        if prog in _EGRESS:
            for h in extract_targets([prog] + toks[i + 1:]):
                if h in _LOCAL:
                    continue
                if not in_scope(scope, h):
                    return False, f"session pivot to out-of-scope host '{h}' via {prog}"
    return True, ""

DEFAULT_ALLOW = frozenset({
    "nmap", "curl", "httpx", "whatweb", "nikto", "gobuster", "ffuf",
    "wpscan", "nuclei", "dig", "whois"})

# Exploitation tools — available to the agent by default (it only runs against an
# authorized, in-scope target; the scope wall still vets every destination). More
# can be added per engagement via config.offensive_agent.allow_bins.
OFFENSIVE_ALLOW = frozenset({
    "sqlmap", "hydra", "medusa", "wget", "nc", "ncat", "feroxbuster", "wfuzz",
    "smbclient", "smbmap", "enum4linux", "crackmapexec", "redis-cli",
    # Kali arsenal — use existing tools, don't hand-write exploits
    "msfconsole", "msfvenom", "searchsploit", "exploitdb"})

# Tools that work locally or carry their target internally (metasploit's RHOSTS
# lives inside -x); allowed without a separately-parseable in-scope target. Still
# allowlist-gated, still egress-denied, and any out-of-scope IP anywhere in the
# command is still blocked (see vet).
_NO_TARGET_OK = frozenset({"searchsploit", "msfvenom", "exploitdb", "msfconsole"})
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_LOOPBACK = frozenset({"127.0.0.1", "0.0.0.0"})

# Write/output/exfil flags — denied for every tool.
_DENY_ARGS = frozenset({"-O", "--upload-file", "--data-binary"})
# Egress-redirect flags — deny only for the HTTP clients that use them this way
# (curl/wget). Other tools reuse some of these letters differently (msfconsole -x
# runs commands; curl -x is a proxy), so they must be tool-scoped.
_PROXY_FLAGS = frozenset({"-x", "--proxy", "--preproxy", "--socks4", "--socks5",
                          "--socks5-hostname", "--connect-to", "--resolve"})
_PROXY_TOOLS = frozenset({"curl", "wget"})


@dataclass
class Verdict:
    blocked: bool
    reason: str = ""


class ScopeGuard:
    def __init__(self, scope: dict, allow_bins, judge_fn=None):
        self.scope = scope or {}
        self.allow = set(allow_bins or ())
        self.judge_fn = judge_fn

    def vet(self, argv: list[str]) -> Verdict:
        if not argv:
            return Verdict(True, "empty command")
        if argv[0] not in self.allow:
            return Verdict(True, f"binary '{argv[0]}' not in allow-list")
        for a in argv[1:]:
            # case-SENSITIVE: curl flags differ by case (-X method vs -x proxy,
            # -O remote-name vs -o outfile), so never lowercase before matching.
            if a in _DENY_ARGS or a.startswith("-o") or a.startswith("--output") \
                    or "file://" in a.lower():
                return Verdict(True, f"write/output flag '{a}' denied")
            if argv[0] in _PROXY_TOOLS and a in _PROXY_FLAGS:
                return Verdict(True, f"proxy/egress flag '{a}' denied")
        targets = extract_targets(argv)
        if not targets:
            # A local/arsenal tool (searchsploit, msfvenom, metasploit) has no
            # separately-parseable connect target — allow it, but still block any
            # out-of-scope IP appearing anywhere in the command (e.g. an msf RHOSTS
            # inside -x). Other tools stay fail-closed: no target => blocked.
            if argv[0] not in _NO_TARGET_OK:
                return Verdict(True, "no in-scope target could be parsed (fail-closed)")
            for ip in _IPV4.findall(" ".join(argv)):
                if ip not in _LOOPBACK and not in_scope(self.scope, ip):
                    return Verdict(True, f"references out-of-scope host '{ip}'")
        else:
            for t in targets:
                if not in_scope(self.scope, t):
                    return Verdict(True, f"target '{t}' is out of scope")
        if self.judge_fn:
            reason = self.judge_fn(argv)
            if reason:
                return Verdict(True, f"judge blocked: {reason}")
        return Verdict(False, "")
