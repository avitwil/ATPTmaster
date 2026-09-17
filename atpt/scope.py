"""Scope oracle — the Python-side gate every intrusive module MUST call before
touching a host. Mirrors recon/recon_runner.sh's shell oracle: explicit
out-of-scope deny always wins; otherwise a host is in scope only if it matches an
in-scope domain (exact, subdomain, or a `*.domain` wildcard) or falls inside an
in-scope CIDR. Stdlib-only. Fail-closed: anything not positively matched is OUT."""
from __future__ import annotations
import ipaddress
import re


def _host_of(target: str) -> str:
    h = re.sub(r"^\w+://", "", (target or "").strip().lower())
    h = h.split("/")[0]              # drop path/query
    if "@" in h:                     # drop userinfo (user:pass@host)
        h = h.split("@")[-1]
    if h.startswith("["):            # bracketed IPv6 literal, e.g. [::1]:8080
        return h[1:].split("]")[0]
    if h.count(":") >= 2:            # bare IPv6 literal (a port needs brackets)
        return h
    return h.split(":")[0]           # host:port -> drop port


def _norm(d: str) -> str:
    return str(d).lower().lstrip("*").lstrip(".")


def in_scope(scope: dict, target: str) -> bool:
    scope = scope or {}
    host = _host_of(target)
    if not host:
        return False
    for d in scope.get("out_of_scope", []) or []:      # explicit domain deny wins
        d = _norm(d)
        if host == d or host.endswith("." + d):
            return False
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    if ip is not None:                                 # explicit IP/CIDR deny wins too
        for c in scope.get("out_of_scope_cidrs", []) or []:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return False
            except ValueError:
                continue
    for d in scope.get("in_scope_domains", []) or []:
        d = _norm(d)
        if host == d or host.endswith("." + d):
            return True
    if ip is not None:
        for c in scope.get("in_scope_cidrs", []) or []:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
    return False
