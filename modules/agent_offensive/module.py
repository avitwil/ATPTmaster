"""LLM offensive agent module. Opt-in via config.offensive_agent.enabled. Wires
the reasoning ladder to the ReAct loop through the ScopeGuard. No-op when off."""
from __future__ import annotations
import ipaddress
import json

from atpt.module import Module, ModuleResult
from atpt.toolbox import Toolbox

from .distill import distill
from .guard import ScopeGuard, DEFAULT_ALLOW, OFFENSIVE_ALLOW
from .loop import run_loop
from .executor import execute, harvest


def _substitutions(scope: dict) -> dict:
    """Map concrete in-scope single hosts to {TARGET} so distilled steps generalise."""
    subs = {}
    for d in (scope or {}).get("in_scope_domains", []) or []:
        h = str(d).lower().lstrip("*").lstrip(".")
        if h:
            subs[h] = "{TARGET}"
    for c in (scope or {}).get("in_scope_cidrs", []) or []:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            subs[str(net.network_address)] = "{TARGET}"
    return subs


class AgentOffensive(Module):
    def run(self, ctx) -> ModuleResult:
        cfg = (json.loads(ctx.engagement.get("config") or "{}").get("offensive_agent") or {})
        if not cfg.get("enabled"):
            return ModuleResult(ok=True, summary="offensive agent disabled")
        if ctx.dry_run:
            return ModuleResult(planned=["agent_offensive: would drive an LLM scan/exploit loop"],
                                summary="dry-run: offensive agent planned")
        allow = set(DEFAULT_ALLOW) | set(OFFENSIVE_ALLOW) | set(cfg.get("allow_bins", []) or [])
        guard = ScopeGuard(ctx.scope, allow)   # judge_fn deferred (Phase 2)
        max_steps = int(cfg.get("max_steps", 20))
        step_timeout = int(cfg.get("step_timeout", 300))

        def emit(kind, message, level="info", data=None):
            ctx.emit(kind, message, level=level, phase="exploit", module=self.id, data=data)

        toolbox = Toolbox(ctx.project_dir / "toolbox")
        toolbox.reindex()
        subs = _substitutions(ctx.scope)
        prov = {"engagement": ctx.engagement.get("id")}

        def distill_fn(goal, transcript):
            return distill(goal=goal, transcript=transcript,
                           reason_fn=lambda p: ctx.reason(p, "exploit"),
                           substitutions=subs, provenance=prov)

        assets, findings, summary = run_loop(
            goal=ctx.goals or "Capture the flags on the in-scope target(s).",
            guard=guard, scope=ctx.scope, reason_fn=lambda p: ctx.reason(p, "exploit"),
            max_steps=max_steps, emit=emit,
            execute_fn=lambda argv: execute(argv, timeout=step_timeout),
            harvest_fn=harvest, toolbox=toolbox, distill_fn=distill_fn)
        emit("agent_done", f"[agent] {summary}", data={"assets": len(assets)})
        return ModuleResult(assets=assets, findings=findings, summary=summary, ok=True)
