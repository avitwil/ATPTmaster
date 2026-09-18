"""Run a vetted command and harvest structured assets from its output. Execution
delegates to toolwrap (never raises; missing binary => rc -1). Harvesting is
deliberately conservative in v1 (nmap open-port lines -> service assets)."""
from __future__ import annotations
import re

from atpt import toolwrap

from .targets import extract_targets

_PORT = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)


def execute(argv, timeout: int = 300, runner=None) -> dict:
    runner = runner or toolwrap.run
    rc, out, err = runner(argv, timeout=timeout)
    return {"rc": rc, "out": out or "", "err": err or ""}


def harvest(argv, result: dict):
    assets = []
    if argv and argv[0] == "nmap" and result.get("rc") == 0:
        hosts = extract_targets(argv) or [""]
        host = hosts[0]
        for port, svc in _PORT.findall(result.get("out", "")):
            assets.append({
                "source_tool": "agent_nmap", "asset_type": "service",
                "host": host, "ip": host, "port": int(port), "protocol": "tcp",
                "service": svc, "value": f"{host}:{port}/{svc}"})
    return assets, []
