"""ScopeGuard: the authoritative pre-execution gate. Deterministic first — the
target of every command must be in scope (fail-closed), the binary must be
allow-listed, and no write/egress flag may be present. An optional judge_fn (an
LLM) may ADD a block, never remove one."""
from __future__ import annotations
from dataclasses import dataclass

from atpt.scope import in_scope

from .targets import extract_targets

DEFAULT_ALLOW = frozenset({
    "nmap", "curl", "httpx", "whatweb", "nikto", "gobuster", "ffuf",
    "wpscan", "nuclei", "dig", "whois"})

_DENY_ARGS = frozenset({"-o", "--output", "-O", "--upload-file", "--data-binary"})


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
            al = a.lower()
            if al in _DENY_ARGS or al.startswith("-o") or "file://" in al:
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
