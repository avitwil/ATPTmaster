"""PTES-compliant Markdown reporter (native).

Renders the engagement's findings into a PTES-shaped report: executive summary,
methodology, per-finding detail (severity, CVSS, OWASP, affected asset, evidence,
remediation) and a raw-evidence appendix. `build_report_md` is a pure helper the
web layer also calls for on-demand downloads. Honors ctx.dry_run (no file write).
"""
from __future__ import annotations
import json
from datetime import date
from pathlib import Path

from atpt.module import Module, ModuleResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_REMEDIATION = {
    "A01": "Enforce authorization checks server-side; deny by default; test for IDOR/privilege escalation.",
    "A02": "Disable cleartext protocols; enforce TLS everywhere; rotate exposed secrets.",
    "A03": "Use parameterized queries and context-aware output encoding to eliminate injection/XSS.",
    "A05": "Harden configuration; restrict network exposure; apply least privilege; remove defaults.",
    "A06": "Upgrade/patch the affected component to a fixed version; track it in inventory.",
    "A07": "Require MFA, strong credential policy, and account lockout; disable unused accounts.",
}
_DEFAULT_REMEDIATION = "Review against vendor guidance and remediate; re-test after the fix."


def _load_evidence(f: dict) -> dict:
    ev = f.get("evidence")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            return {"raw": ev}
    return ev if isinstance(ev, dict) else {}


def _sev_counts(findings: list[dict]) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        out[sev] = out.get(sev, 0) + 1
    return out


def build_report_md(store, eid: str, project_dir: Path) -> str:
    eng = store.get_engagement(eid) or {"id": eid, "name": eid, "scope": "{}"}
    scope = json.loads(eng.get("scope") or "{}")
    all_findings = store.list_findings(eid)
    reported = [f for f in all_findings if f.get("status") != "false_positive"]
    reported.sort(key=lambda f: (_SEV_ORDER.get((f.get("severity") or "info").lower(), 9),
                                 -(f.get("cvss") or 0)))
    assets = store.list_assets(eid)
    counts = _sev_counts(reported)
    validated = sum(1 for f in reported if f.get("status") == "validated")

    L = []
    L.append(f"# Penetration Test Report — {eng.get('name') or eid}")
    L.append("")
    L.append(f"- **Engagement:** `{eid}`")
    L.append(f"- **Date:** {date.today().isoformat()}")
    domains = ", ".join(scope.get("in_scope_domains", []) or []) or "—"
    cidrs = ", ".join(scope.get("in_scope_cidrs", []) or []) or "—"
    L.append(f"- **In-scope domains:** {domains}")
    L.append(f"- **In-scope networks:** {cidrs}")
    L.append(f"- **Standard:** PTES · CVSS · OWASP Top 10")
    L.append("")

    L.append("## Executive Summary")
    L.append("")
    if reported:
        sev_line = ", ".join(f"{counts[s]} {s}" for s in
                             sorted(counts, key=lambda s: _SEV_ORDER.get(s, 9)))
        L.append(f"The assessment identified **{len(reported)} finding(s)** "
                 f"({sev_line}); **{validated} validated**. "
                 f"Reconnaissance enumerated {len(assets)} in-scope asset(s).")
    else:
        L.append("No findings were reported for this engagement.")
    L.append("")

    L.append("## Methodology")
    L.append("")
    L.append("Phases executed: scope → recon → map (attack-surface routing) → "
             "exploit → validate (verification-first) → report. Findings below are "
             "derived from discovered assets, triaged by confidence, and — where "
             "marked validated — confirmed by the verification stage.")
    L.append("")

    L.append("## Findings")
    L.append("")
    if not reported:
        L.append("_None._")
    for i, f in enumerate(reported, 1):
        ev = _load_evidence(f)
        sev = (f.get("severity") or "info").lower()
        owasp = f.get("owasp") or "—"
        cvss = f.get("cvss")
        L.append(f"### {i}. {f.get('title') or 'Untitled finding'}")
        L.append("")
        L.append(f"- **Severity:** {sev}  |  **Status:** {f.get('status') or 'candidate'}")
        L.append(f"- **CVSS:** {cvss if cvss is not None else '—'}  |  **OWASP:** {owasp}")
        affected = ev.get("asset_value") or (f.get("source_tool") or "—")
        L.append(f"- **Affected:** `{affected}`")
        L.append(f"- **Evidence:** `{json.dumps(ev, ensure_ascii=False)}`")
        rem = _REMEDIATION.get(str(owasp).split()[0] if owasp else "", _DEFAULT_REMEDIATION)
        L.append(f"- **Remediation:** {rem}")
        L.append("")

    L.append("## Appendix A — Discovered Assets (raw evidence)")
    L.append("")
    if not assets:
        L.append("_None._")
    for a in assets:
        L.append(f"- `{a.get('asset_type')}` — `{a.get('value')}`"
                 + (f" (tool: {a.get('source_tool')})" if a.get("source_tool") else ""))
    L.append("")
    return "\n".join(L)


class ReportPTES(Module):
    def run(self, ctx) -> ModuleResult:
        eid = ctx.engagement["id"]
        md = build_report_md(ctx.store, eid, ctx.project_dir)
        out = Path(ctx.project_dir) / "var" / "reports" / f"{eid}.md"
        if ctx.dry_run:
            ctx.emit("dry_run", f"[report] would write PTES report ({len(md)} bytes) to {out}",
                     phase="report", module=self.id)
            return ModuleResult(planned=[f"write {out}"],
                                summary=f"dry-run: PTES report planned ({len(md)} bytes)")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        ctx.emit("report_done", f"[report] PTES report written to {out}",
                 phase="report", module=self.id, data={"path": str(out), "bytes": len(md)})
        return ModuleResult(summary=f"PTES report written to {out}")
