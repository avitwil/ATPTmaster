"""Read-only cloud posture audit via prowler. Runs only when
`config.cloud.provider` (aws|gcp|azure|kubernetes) is set; credentials come from
the operator's own environment (never handled here). Emits a finding per failed
check. Non-intrusive (read-only audit). No-op if prowler is absent or no cloud
target is configured. Covers the Cloud domain of the scope."""
from __future__ import annotations
import json

from atpt.module import Module, ModuleResult
from atpt import toolwrap

_SEV = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "informational": 1.0}


def parse_prowler(stdout: str) -> list[dict]:
    """Parse prowler JSON/OCSF-style JSONL; keep FAILed checks as findings."""
    out = []
    for line in stdout.splitlines():
        line = line.strip().rstrip(",")
        if not line or line[0] not in "{[":
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows = r if isinstance(r, list) else [r]
        for c in rows:
            if not isinstance(c, dict):
                continue
            status = str(c.get("status_code") or c.get("status") or "").upper()
            if status not in ("FAIL", "FAILED"):
                continue
            info = c.get("finding_info") or {}
            sev = str(c.get("severity") or info.get("severity") or "medium").lower()
            out.append({
                "domain": "Cloud", "owasp": "A05", "status": "candidate",
                "source_tool": "prowler",
                "title": info.get("title") or c.get("check_title") or c.get("check_id") or "Cloud misconfiguration",
                "severity": sev if sev in _SEV else "medium", "cvss": _SEV.get(sev, 5.0),
                "evidence": {"check_id": c.get("check_id") or info.get("uid"),
                             "resource": c.get("resource_uid") or c.get("resource_id"),
                             "source": "prowler"}})
    return out


class ReconCloud(Module):
    def run(self, ctx) -> ModuleResult:
        cfg = json.loads(ctx.engagement.get("config") or "{}").get("cloud", {})
        provider = cfg.get("provider")
        if not provider:
            return ModuleResult(summary="no cloud target configured; skipped")
        if ctx.dry_run:
            ctx.emit("dry_run", f"[cloud] would audit {provider} with prowler",
                     phase="recon", module=self.id)
            return ModuleResult(planned=[f"prowler {provider}"],
                                summary=f"dry-run: would audit {provider}")
        argv = ["prowler", provider, "--output-formats", "json-ocsf",
                "--output-directory", "/dev/stdout"]
        rc, out, err = toolwrap.run(argv, timeout=cfg.get("timeout", 1800))
        if rc == -1:
            ctx.emit("prowler_absent", "[cloud] prowler not installed — skipping", "warn",
                     phase="recon", module=self.id)
            return ModuleResult(summary="prowler not installed; skipped")
        findings = parse_prowler(out)
        ctx.emit("cloud_done", f"[cloud] {len(findings)} failed checks ({provider})",
                 phase="recon", module=self.id, data={"findings": len(findings)})
        return ModuleResult(findings=findings, summary=f"{len(findings)} cloud findings ({provider})")
