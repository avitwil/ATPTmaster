"""Scope oracle — the Python-side gate every intrusive module MUST call before
touching a host. Mirrors recon/recon_runner.sh's shell oracle: explicit
out-of-scope deny always wins; otherwise a host is in scope only if it matches an
in-scope domain (exact or subdomain) or falls inside an in-scope CIDR.
Stdlib-only. Fail-closed: anything not positively matched is OUT of scope."""
from __future__ import annotations
import ipaddress
import re


def _host_of(target: str) -> str:
    h = re.sub(r"^\w+://", "", (target or "").strip().lower())
    return h.split("/")[0].split(":")[0]


def in_scope(scope: dict, target: str) -> bool:
    scope = scope or {}
    host = _host_of(target)
    if not host:
        return False
    for d in scope.get("out_of_scope", []) or []:      # explicit deny wins
        d = str(d).lower().lstrip(".")
        if host == d or host.endswith("." + d):
            return False
    for d in scope.get("in_scope_domains", []) or []:
        d = str(d).lower().lstrip(".")
        if host == d or host.endswith("." + d):
            return True
    try:
        ip = ipaddress.ip_address(host)
        for c in scope.get("in_scope_cidrs", []) or []:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False
