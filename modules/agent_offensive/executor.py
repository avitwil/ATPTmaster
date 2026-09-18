"""Run a vetted command and harvest structured assets from its output. Execution
delegates to toolwrap (never raises; missing binary => rc -1). Harvesting turns
nmap open-port lines into service assets and any successful web-tool hit into a
web_endpoint asset, so the operator sees results as the agent works."""
from __future__ import annotations
import re

from atpt import toolwrap

from .targets import extract_targets

_PORT = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)
_WEB_BINS = frozenset({"curl", "whatweb", "httpx", "nikto", "gobuster", "ffuf", "wpscan"})
_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.MULTILINE)
_FOUND = re.compile(r"https?://\S+", re.IGNORECASE)


def execute(argv, timeout: int = 300, runner=None) -> dict:
    runner = runner or toolwrap.run
    rc, out, err = runner(argv, timeout=timeout)
    return {"rc": rc, "out": out or "", "err": err or ""}


def _first_url(argv):
    for tok in argv[1:]:
        if "://" in tok:
            return tok
    return None


def harvest(argv, result: dict):
    assets = []
    if not argv:
        return assets, []
    rc = result.get("rc")
    out = result.get("out", "")
    if argv[0] == "nmap" and rc == 0:
        host = (extract_targets(argv) or [""])[0]
        for port, svc in _PORT.findall(out):
            assets.append({
                "source_tool": "agent_nmap", "asset_type": "service",
                "host": host, "ip": host, "port": int(port), "protocol": "tcp",
                "service": svc, "value": f"{host}:{port}/{svc}"})
    elif argv[0] in _WEB_BINS and rc == 0:
        url = _first_url(argv)
        if url:
            m = _STATUS.search(out)
            assets.append({
                "source_tool": f"agent_{argv[0]}", "asset_type": "web_endpoint",
                "host": extract_targets([argv[0], url])[0] if extract_targets([argv[0], url]) else "",
                "url": url, "http_status": int(m.group(1)) if m else None, "value": url})
            # content-discovery tools surface additional paths in their output
            if argv[0] in ("gobuster", "ffuf", "nikto"):
                seen = {url}
                for found in _FOUND.findall(out)[:25]:
                    if found not in seen:
                        seen.add(found)
                        assets.append({"source_tool": f"agent_{argv[0]}",
                                       "asset_type": "web_path", "url": found, "value": found})
    return assets, []
