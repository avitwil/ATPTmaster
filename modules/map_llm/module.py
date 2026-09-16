"""Flags in-scope web assets that look like LLM/chat applications as
prompt-injection TEST surfaces (OWASP LLM01). Non-intrusive: a deterministic
heuristic over recon output that marks candidates for the operator / exploit
phase — it sends no injection payloads. Covers the LLM domain of the scope."""
from __future__ import annotations
import json

from atpt.module import Module, ModuleResult

LLM_HINTS = ("chat", "gpt", "llm", "assistant", "chatbot", "openai", "copilot",
             "/v1/chat", "/api/chat", "completion", "genai", "bard", "claude")


def _text(a: dict) -> str:
    parts = [a.get("url") or a.get("value") or "", a.get("http_title") or ""]
    tech = a.get("tech")
    if tech:
        parts.append(tech if isinstance(tech, str) else json.dumps(tech))
    return " ".join(parts).lower()


class MapLLM(Module):
    def run(self, ctx) -> ModuleResult:
        eid = ctx.engagement["id"]
        findings = []
        for a in ctx.store.list_assets(eid):
            if a.get("asset_type") not in ("web_endpoint", "web_path"):
                continue
            hit = next((h for h in LLM_HINTS if h in _text(a)), None)
            if not hit:
                continue
            findings.append({
                "asset_id": a.get("id"), "domain": "LLM",
                "title": "LLM prompt-injection test surface",
                "severity": "medium", "cvss": 6.5, "owasp": "LLM01",
                "status": "candidate", "source_tool": "map_llm",
                "evidence": {"asset_value": a.get("value"), "hint": hit,
                             "rule": "llm_surface", "priority": 58, "provenance": "rules"}})
        if ctx.dry_run:
            ctx.emit("dry_run", f"[map_llm] would flag {len(findings)} LLM surfaces",
                     phase="map", module=self.id)
            return ModuleResult(planned=[f"flag {len(findings)} LLM surfaces"],
                                summary=f"dry-run: {len(findings)} LLM surfaces")
        ctx.emit("map_llm_done", f"[map_llm] {len(findings)} LLM prompt-injection surfaces",
                 phase="map", module=self.id, data={"findings": len(findings)})
        return ModuleResult(findings=findings, summary=f"{len(findings)} LLM surfaces flagged")
