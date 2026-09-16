"""Active vulnerability scan via nuclei over in-scope web/API/infra assets.
Intrusive (sends probes) -> gated by approval in semi mode. No-op if nuclei is
absent. Scope is enforced per target before any probe. Covers the Web / API /
Infra CVE surface of the engagement scope."""
from __future__ import annotations
import json

from atpt.module import Module, ModuleResult
from atpt.scope import in_scope
from atpt import toolwrap


def _targets(assets, scope):
    out = []
    for a in assets:
        if a.get("asset_type") not in ("web_endpoint", "web_path"):
            continue
        url = a.get("url") or a.get("value")
        if url and in_scope(scope, url):
            out.append((a.get("id"), url))
    return out


class ScanNuclei(Module):
    def run(self, ctx) -> ModuleResult:
        eid = ctx.engagement["id"]
        cfg = json.loads(ctx.engagement.get("config") or "{}").get("nuclei", {})
        targets = _targets(ctx.store.list_assets(eid), ctx.scope)

        if ctx.dry_run:
            ctx.emit("dry_run", f"[nuclei] would scan {len(targets)} in-scope web assets",
                     phase="map", module=self.id)
            return ModuleResult(planned=[f"nuclei scan {len(targets)} in-scope targets"],
                                summary=f"dry-run: nuclei would scan {len(targets)} targets")

        findings, rate = [], cfg.get("rate", 150)
        for asset_id, url in targets:
            argv = ["nuclei", "-silent", "-jsonl", "-rate-limit", str(rate), "-u", url]
            if cfg.get("severity"):
                argv += ["-severity", cfg["severity"]]
            rc, out, err = toolwrap.run(argv, timeout=cfg.get("timeout", 600))
            if rc == -1:
                ctx.emit("nuclei_absent", "[nuclei] not installed — skipping", "warn",
                         phase="map", module=self.id)
                return ModuleResult(summary="nuclei not installed; skipped")
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = r.get("info", {}) if isinstance(r.get("info"), dict) else {}
                findings.append({
                    "asset_id": asset_id, "domain": "Web",
                    "title": info.get("name") or r.get("template-id") or "nuclei finding",
                    "severity": (info.get("severity") or "info").lower(),
                    "owasp": "A06", "status": "candidate", "source_tool": "nuclei",
                    "evidence": {"template": r.get("template-id"),
                                 "matched_at": r.get("matched-at") or r.get("matched_at"),
                                 "url": url, "source": "nuclei"}})
        ctx.emit("nuclei_done", f"[nuclei] {len(findings)} findings from {len(targets)} targets",
                 phase="map", module=self.id, data={"findings": len(findings)})
        return ModuleResult(findings=findings,
                            summary=f"{len(findings)} nuclei findings from {len(targets)} in-scope targets")
