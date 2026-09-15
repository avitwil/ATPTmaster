"""Deterministic asset -> candidate-finding mapping — the PTT decomposition
expressed as rules. Pure functions, no I/O. Each rule returns zero or more
candidate finding dicts; map_assets() runs them all, dedupes, and ranks."""
from __future__ import annotations

import json

SENSITIVE_PATHS = ("/admin", "/login", "/.git", "/.env", "/actuator",
                   "/config", "/backup", "/phpmyadmin", "/wp-admin")
DATA_SERVICES = ("mysql", "postgres", "postgresql", "redis", "mongo",
                 "mongodb", "mssql", "oracle", "elasticsearch", "memcached")
CLEARTEXT_SERVICES = ("ftp", "telnet")


def _cand(asset, title, domain, owasp, severity, cvss, rule, priority):
    return {"asset_id": asset.get("id"), "title": title, "domain": domain,
            "owasp": owasp, "severity": severity, "cvss": cvss,
            "status": "candidate", "source_tool": "map_ptt",
            "evidence": {"asset_value": asset.get("value"), "rule": rule,
                         "priority": priority, "provenance": "rules"}}


def _svc(a):
    return (a.get("service") or "").lower()


def _rule_ssh(a):
    if _svc(a) == "ssh" or a.get("port") == 22:
        return [_cand(a, "SSH credential attack surface", "Infra", "A07",
                      "medium", 5.3, "ssh_surface", 60)]
    return []


def _rule_cleartext(a):
    if _svc(a) in CLEARTEXT_SERVICES:
        return [_cand(a, f"Cleartext service exposed ({_svc(a)})", "Infra", "A02",
                      "medium", 5.9, "cleartext_service", 55)]
    return []


def _rule_data_service(a):
    if _svc(a) in DATA_SERVICES:
        return [_cand(a, f"Exposed data service ({_svc(a)})", "Infra", "A05",
                      "high", 7.5, "exposed_data_service", 82)]
    return []


def _rule_web_known_tech(a):
    if a.get("asset_type") != "web_endpoint":
        return []
    # store.list_assets returns list-valued columns (e.g. "tech") as a
    # JSON-encoded string, since upsert_asset JSON-encodes list values on
    # write. Decode it back into a list before iterating; a plain
    # non-JSON string (e.g. "nginx") falls through to the single-element
    # [tech] case below, which is still correct.
    tech = a.get("tech")
    if isinstance(tech, str):
        try:
            tech = json.loads(tech)
        except Exception:
            pass
    techs = tech if isinstance(tech, list) else ([tech] if tech else [])
    out = []
    for t in techs:
        if t:
            out.append(_cand(a, f"Known-CVE candidate ({t})", "Web", "A06",
                             "high", 7.0, "known_tech", 78))
    return out


def _rule_sensitive_path(a):
    if a.get("asset_type") != "web_path":
        return []
    url = (a.get("url") or a.get("value") or "").lower()
    for p in SENSITIVE_PATHS:
        if p in url:
            return [_cand(a, f"Sensitive path exposed ({p})", "Web", "A05",
                          "high", 7.5, "sensitive_path", 80)]
    return []


def _rule_auth_protected(a):
    if a.get("http_status") in (401, 403):
        return [_cand(a, "Auth-protected surface (bypass candidate)", "Web", "A01",
                      "medium", 5.0, "auth_protected", 50)]
    return []


def _rule_web_generic(a):
    if a.get("asset_type") == "web_endpoint":
        return [_cand(a, "Web app entry (injection/XSS surface)", "Web", "A03",
                      "low", 3.5, "web_generic", 30)]
    return []


RULES = [_rule_ssh, _rule_cleartext, _rule_data_service, _rule_web_known_tech,
         _rule_sensitive_path, _rule_auth_protected, _rule_web_generic]


def map_assets(assets: list[dict]) -> list[dict]:
    out, seen = [], set()
    for a in assets:
        for rule in RULES:
            for c in rule(a):
                key = (c.get("asset_id"), c["title"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(c)
    out.sort(key=lambda c: c["evidence"]["priority"], reverse=True)
    return out
