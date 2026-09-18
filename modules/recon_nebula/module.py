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
from atpt.config import offensive_agent_on


def _scan_targets(scope) -> list:
    """Concrete hosts to scan: in-scope domains + CIDRs, dropping the UI's "all"
    sentinel (the settings form stores 'in': ['all'] for a whole category to mean
    "everything discovered in scope", NOT a literal host — passing it as
    `--target all` just makes naabu/nmap waste time failing to resolve "all")."""
    scope = scope or {}
    raw = (scope.get("in_scope_domains", []) or []) + (scope.get("in_scope_cidrs", []) or [])
    out, seen = [], set()
    for t in raw:
        t = str(t or "").strip()
        if not t or t.lower() == "all" or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


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
        targets = _scan_targets(ctx.scope)
        tflags = " ".join(f"--target {shlex.quote(t)}" for t in targets)
        return (f"{shlex.quote(str(runner))} --engagement {shlex.quote(ctx.engagement['id'])} "
                f"--scope {shlex.quote(str(scope_file))} --tools {shlex.quote(tools)} "
                f"--rate {rate} {tflags}")

    def plan(self, ctx):
        return [f"recon_nebula: exec {self._command(ctx)}"]

    def run(self, ctx) -> ModuleResult:
        if offensive_agent_on(ctx.engagement):
            return ModuleResult(ok=True, summary="skipped: offensive agent is the active engine")
        # No concrete host in scope -> the runner would die "no --target provided"
        # (exit 2). Say so plainly instead, so the operator knows to add a target
        # IP/domain rather than seeing a cryptic recon failure.
        if not ctx.dry_run and not _scan_targets(ctx.scope):
            ctx.emit("recon_no_target",
                     "[recon] no scannable target in scope — add a target host/IP "
                     "(or CIDR) to the engagement's in-scope list, then run recon again.",
                     phase="recon", module=self.id, level="warn")
            # ok=False: not a real completion — recon must re-run once a target is added.
            return ModuleResult(assets=[], summary="no in-scope target to scan", ok=False)
        cmd = self._command(ctx)
        if ctx.dry_run:
            ctx.emit("dry_run", f"[recon] would exec: {cmd}", phase="recon", module=self.id)
            return ModuleResult(planned=[cmd], summary="dry-run: recon planned, no tools executed")
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        assets = _normalize(proc.stdout)
        # A non-zero exit is a real recon FAILURE (scope/target/tooling error) — it
        # must NOT be marked completed, or recon never re-runs and the pipeline is
        # stuck with 0 assets. exit 0 with 0 assets is a valid "found nothing".
        ok = proc.returncode == 0
        ctx.emit("recon_done", f"[recon] normalized {len(assets)} assets (exit={proc.returncode})",
                 phase="recon", module=self.id, level="info" if ok else "warn",
                 data={"exit": proc.returncode, "stderr_tail": proc.stderr[-500:]})
        return ModuleResult(assets=assets, summary=f"{len(assets)} assets discovered", ok=ok)
