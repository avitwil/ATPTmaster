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
    "smbclient", "smbmap", "enum4linux", "crackmapexec", "redis-cli"})

_DENY_ARGS = frozenset({
    "-o", "--output", "-O", "--upload-file", "--data-binary",
    # egress redirect: these can route the connection to an off-scope host,
    # so the URL scope-check would no longer reflect where traffic actually goes.
    "-x", "--proxy", "--preproxy", "--socks4", "--socks5", "--socks5-hostname",
    "--connect-to", "--resolve"})


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
                return Verdict(True, f"write/egress flag '{a}' denied")
        targets = extract_targets(argv)
        if not targets:
            return Verdict(True, "no in-scope target could be parsed (fail-closed)")
        for t in targets:
            if not in_scope(self.scope, t):
                return Verdict(True, f"target '{t}' is out of scope")
        if self.judge_fn:
            reason = self.judge_fn(argv)
            if reason:
                return Verdict(True, f"judge blocked: {reason}")
        return Verdict(False, "")
