"""Recon module — extraction of Nebula's CLI-wrapper pattern.

Delegates tool orchestration to recon/recon_runner.sh (which enforces scope),
then normalizes the JSONL into canonical assets. Scope stays enforced at the
tool layer; this module only shapes and persists results.
"""
from __future__ import annotations
import json
import shlex
import subprocess
from pathlib import Path

from atpt.module import Module, ModuleResult


def _host_of(v):
    if not v:
        return None
    v = str(v).split("://")[-1]
    return v.split("/")[0].split(":")[0]


def _normalize(stdout: str) -> list[dict]:
    seen, out = set(), []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tool = r.get("_tool", "unknown")
        a = {"source_tool": tool, "raw": r}
        if tool == "subfinder":
            a.update(asset_type="subdomain", host=r.get("host") or r.get("input"),
                     value=r.get("host") or r.get("input"))
        elif tool == "naabu":
            hp = f"{r.get('host') or r.get('ip')}:{r.get('port')}"
            a.update(asset_type="service", host=r.get("host") or r.get("ip"),
                     ip=r.get("ip"), port=r.get("port"), protocol="tcp", value=hp)
        elif tool == "nmap":
            a.update(asset_type="service", host=r.get("host") or r.get("ip"), ip=r.get("ip"),
                     port=r.get("port"), protocol=r.get("protocol") or "tcp",
                     service=r.get("service"), product=r.get("product"), version=r.get("version"),
                     value=f"{r.get('host') or r.get('ip')}:{r.get('port')}/{r.get('service') or ''}")
        elif tool == "httpx":
            a.update(asset_type="web_endpoint", host=r.get("host") or _host_of(r.get("input")),
                     ip=(r.get("a") or [None])[0], port=r.get("port"), protocol="tcp",
                     service=r.get("scheme"), http_status=r.get("status_code"),
                     http_title=r.get("title"), tech=r.get("tech") or r.get("technologies"),
                     url=r.get("url"), value=r.get("url"))
        elif tool == "ffuf":
            a.update(asset_type="web_path", host=_host_of(r.get("base")), url=r.get("url"),
                     http_status=r.get("status"), value=r.get("url"))
        else:
            a.update(asset_type="unknown", value=json.dumps(r)[:200])
        if not a.get("value"):
            continue
        key = (a["asset_type"], a["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


class ReconNebula(Module):
    def _command(self, ctx) -> str:
        runner = ctx.project_dir / "recon" / "recon_runner.sh"
        # UI/demo engagements don't write a scope file, but recon_runner.sh requires
        # one (else it dies with exit 2). Persist the derived scope to a real path.
        var = Path(ctx.project_dir) / "var"
        var.mkdir(parents=True, exist_ok=True)
        scope_file = var / f"{ctx.engagement['id']}.scope.json"
        scope_file.write_text(json.dumps(ctx.scope or {}))
        cfg = json.loads(ctx.engagement.get("config") or "{}")
        # nmap is in the default chain so a bare Kali box (no go-tools) still port-scans.
        tools = cfg.get("recon_tools", "subfinder,naabu,nmap,httpx,ffuf")
        rate = cfg.get("rate", 150)
        targets = (ctx.scope.get("in_scope_domains", []) or []) + (ctx.scope.get("in_scope_cidrs", []) or [])
        tflags = " ".join(f"--target {shlex.quote(t)}" for t in targets)
        return (f"{shlex.quote(str(runner))} --engagement {shlex.quote(ctx.engagement['id'])} "
                f"--scope {shlex.quote(str(scope_file))} --tools {shlex.quote(tools)} "
                f"--rate {rate} {tflags}")

    def plan(self, ctx):
        return [f"recon_nebula: exec {self._command(ctx)}"]

    def run(self, ctx) -> ModuleResult:
        cmd = self._command(ctx)
        if ctx.dry_run:
            ctx.emit("dry_run", f"[recon] would exec: {cmd}", phase="recon", module=self.id)
            return ModuleResult(planned=[cmd], summary="dry-run: recon planned, no tools executed")
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        assets = _normalize(proc.stdout)
        ctx.emit("recon_done", f"[recon] normalized {len(assets)} assets (exit={proc.returncode})",
                 phase="recon", module=self.id,
                 data={"exit": proc.returncode, "stderr_tail": proc.stderr[-500:]})
        return ModuleResult(assets=assets, summary=f"{len(assets)} assets discovered")
