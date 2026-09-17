"""Orchestrator: resolves which modules apply, runs them per mode.

Run modes:
  step  — run exactly one pending module, then stop (human drives each step).
  semi  — auto-run non-intrusive modules; pause + request approval before intrusive ones.
  full  — auto-run everything runnable. Scope is still enforced inside each tool module.
"""
from __future__ import annotations
import json
from pathlib import Path

from .module import PHASES, Module, RunContext
from .reasoning import ReasoningLadder


class Orchestrator:
    def __init__(self, store, modules: dict[str, Module], project_dir: Path):
        self.store = store
        self.modules = modules
        self.project_dir = Path(project_dir)

    def _ordered(self) -> list[Module]:
        return sorted(self.modules.values(),
                      key=lambda m: (PHASES.index(m.manifest.phase), m.manifest.id))

    def _satisfied(self, eng: dict) -> set:
        scope = json.loads(eng.get("scope") or "{}")
        s = set()
        if scope.get("in_scope_domains") or scope.get("in_scope_cidrs"):
            s.add("target")
        if self.store.count_assets(eng["id"]) > 0:
            s.add("asset")
        if self.store.count_findings(eng["id"]) > 0:
            s.add("finding")
        if self.store.count_findings(eng["id"], status="validated") > 0:
            s.add("validated_finding")
        return s

    def _pending(self, eng: dict, mode: str) -> list[Module]:
        done = self.store.completed_modules(eng["id"])
        sat = self._satisfied(eng)
        out = []
        for mod in self._ordered():
            m = mod.manifest
            if not m.enabled or mode not in m.run_modes or m.id in done:
                continue
            if not set(m.consumes).issubset(sat):
                continue
            out.append(mod)
        return out

    @staticmethod
    def _needs_gate(mode: str, mod: Module) -> bool:
        # semi pauses before intrusive; full auto-runs; step is one-at-a-time (implicit consent).
        return mode == "semi" and mod.manifest.intrusive

    def _ctx(self, eng: dict, dry_run: bool) -> RunContext:
        cfg = json.loads(eng.get("config") or "{}")
        # Reasoning: engagement config wins; otherwise fall back to global settings.
        settings = self.store.get_settings() if hasattr(self.store, "get_settings") else {}
        reasoning_cfg = cfg.get("reasoning") or settings.get("reasoning")
        reasoner = ReasoningLadder(
            reasoning_cfg,
            emit=lambda kind, msg, lvl: self.store.add_event(
                eng["id"], None, None, lvl, kind, msg, None))
        goals = (cfg.get("ctf") or {}).get("goals") or ""
        return RunContext(engagement=eng, scope=json.loads(eng.get("scope") or "{}"),
                          store=self.store, project_dir=self.project_dir,
                          dry_run=dry_run, reasoner=reasoner, goals=goals)

    def plan(self, eng: dict, mode: str) -> list[dict]:
        rows = []
        for mod in self._pending(eng, mode):
            rows.append({"id": mod.manifest.id, "phase": mod.manifest.phase,
                         "intrusive": mod.manifest.intrusive,
                         "gated": self._needs_gate(mode, mod)})
        return rows

    def run(self, eng: dict, mode: str, dry_run: bool = False, control=None) -> dict:
        """Process runnable modules. step: one module. semi/full: cascade until
        the queue drains or (semi) an intrusive module needs approval.

        `control`, if given, is called at each module boundary; returning False
        halts the run gracefully (used for operator pause/stop between steps)."""
        eid = eng["id"]
        executed, gated_on, halted = [], None, False
        attempted: set = set()            # processed this call — never reselect (avoids loops)
        while True:
            if control is not None and not control():
                self.store.add_event(eid, None, None, "warn", "run_halted",
                                     "run halted by operator (between steps)", None)
                halted = True
                break
            pending = [m for m in self._pending(eng, mode) if m.id not in attempted]
            if not pending:
                break
            mod = pending[0]

            if self._needs_gate(mode, mod) and not self.store.is_approved(eid, mod.id):
                self.store.request_approval(eid, mod.id, mod.manifest.phase,
                                            "intrusive step requires approval (semi mode)")
                self.store.add_event(eid, mod.manifest.phase, mod.id, "warn", "approval_required",
                                     f"paused before intrusive module '{mod.id}' — run: atpt approve {mod.id}", None)
                gated_on = mod.id
                break

            ctx = self._ctx(eng, dry_run)
            attempted.add(mod.id)
            try:
                res = mod.run(ctx)
            except Exception as exc:      # a flaky module must not kill the engine
                self.store.log_module_run(eid, mod.id, mod.manifest.phase, "error", "", str(exc))
                self.store.add_event(eid, mod.manifest.phase, mod.id, "error", "module_error", str(exc), None)
                if mode == "step":
                    break
                continue

            if not dry_run:               # dry-run plans only — never mutates the State Tree
                for a in res.assets:
                    self.store.upsert_asset(eid, a)
                for f in res.findings:
                    self.store.upsert_finding(eid, f)
            self.store.log_module_run(eid, mod.id, mod.manifest.phase,
                                      "dry" if dry_run else "ok", res.summary, "")
            executed.append(mod.id)
            if mode == "step":
                break
        return {"executed": executed, "gated_on": gated_on, "dry_run": dry_run, "halted": halted}
