"""Map/PTT router — extraction of PentestGPT's task-decomposition concept.
Turns the asset inventory into prioritized CANDIDATE findings via deterministic
rules (rules.py), with optional reasoning-ladder enrichment (ctx.reason).
Non-intrusive: reasons over recon output, touches no target."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path

from atpt.module import Module, ModuleResult

# Load the sibling rules.py by path (the module dir is not on sys.path).
_spec = importlib.util.spec_from_file_location(
    "map_ptt_rules", Path(__file__).with_name("rules.py"))
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)

ENRICH_PROMPT = (
    "You are a penetration-testing triage assistant. Given JSON of discovered "
    "assets and current candidate findings, return ONLY a JSON list of ADDITIONAL "
    "candidate findings as objects with keys: title, domain, severity "
    "(low|medium|high|critical), owasp, cvss (number), asset_id. Return [] if you "
    "have nothing to add.\n\n"
)


class MapPTT(Module):
    def run(self, ctx) -> ModuleResult:
        eid = ctx.engagement["id"]
        assets = ctx.store.list_assets(eid)
        cands = rules.map_assets(assets)

        if ctx.dry_run:
            ctx.emit("dry_run",
                     f"[map] would derive {len(cands)} candidate findings from "
                     f"{len(assets)} assets", phase="map", module=self.id)
            return ModuleResult(
                planned=[f"map {len(assets)} assets -> {len(cands)} candidates"],
                summary=f"dry-run: {len(cands)} candidate findings planned")

        cfg = json.loads(ctx.engagement.get("config") or "{}")
        if cfg.get("map", {}).get("enrich", True):
            cands = self._enrich(ctx, assets, cands)

        ctx.emit("map_done",
                 f"[map] {len(cands)} candidate findings from {len(assets)} assets",
                 phase="map", module=self.id,
                 data={"assets": len(assets), "candidates": len(cands)})
        return ModuleResult(findings=cands,
                            summary=f"{len(cands)} candidate findings from "
                                    f"{len(assets)} assets")

    def _enrich(self, ctx, assets, cands):
        try:
            summary = [{"asset_id": a.get("id"), "value": a.get("value"),
                        "type": a.get("asset_type"), "service": a.get("service"),
                        "tech": a.get("tech"), "http_status": a.get("http_status")}
                       for a in assets]
            prompt = ENRICH_PROMPT + json.dumps(
                {"assets": summary,
                 "candidates": [{"asset_id": c["asset_id"], "title": c["title"]}
                                for c in cands]})
            text = ctx.reason(prompt, phase="map", role="map")
            if not text:
                return cands
            extra = json.loads(text[text.index("["): text.rindex("]") + 1])
            seen = {(c["asset_id"], c["title"]) for c in cands}
            for e in extra:
                key = (e.get("asset_id"), e.get("title"))
                if not e.get("title") or key in seen:
                    continue
                seen.add(key)
                cands.append({"asset_id": e.get("asset_id"), "title": e["title"],
                              "domain": e.get("domain", "Web"),
                              "severity": e.get("severity", "low"),
                              "owasp": e.get("owasp"), "cvss": e.get("cvss"),
                              "status": "candidate", "source_tool": "map_ptt",
                              "evidence": {"rule": "llm_enrich",
                                           "provenance": "reasoning"}})
        except Exception as exc:
            ctx.emit("map_enrich_skipped", f"[map] enrichment skipped: {exc}",
                     "warn", phase="map", module=self.id)
        return cands
