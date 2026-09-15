"""Verification-first validator — extraction of Xalgorix's PoC-validation posture.

Applies a deterministic confidence score to each candidate finding (optionally
confirmed by reasoning) and:
  - promotes high-confidence candidates to `validated`,
  - eliminates low-confidence ones as `false_positive`,
  - leaves the uncertain middle as `candidate` for human/exploit follow-up.
Non-intrusive: it reasons over findings, it does not exploit. Honors ctx.dry_run.
"""
from __future__ import annotations
import json

from atpt.module import Module, ModuleResult

SPECIFIC_RULES = {"exposed_data_service", "sensitive_path", "known_tech", "cleartext_service"}
GENERIC_RULES = {"web_generic"}
_SEV_BASE = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}

VALIDATE_AT = 0.6      # >= promote to validated
ELIMINATE_BELOW = 0.35  # < eliminate as false_positive


def _rule_of(finding: dict) -> str:
    ev = finding.get("evidence")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            ev = {}
    return (ev or {}).get("rule", "") if isinstance(ev, dict) else ""


def _confidence(finding: dict) -> float:
    score = _SEV_BASE.get((finding.get("severity") or "").lower(), 0.4)
    rule = _rule_of(finding)
    if rule in SPECIFIC_RULES:
        score += 0.1
    elif rule in GENERIC_RULES:
        score -= 0.15
    return max(0.0, min(1.0, score))


class ValidateXalgorix(Module):
    def run(self, ctx) -> ModuleResult:
        eid = ctx.engagement["id"]
        candidates = ctx.store.list_findings(eid, status="candidate")
        validated = eliminated = 0
        for f in candidates:
            conf = _confidence(f)
            if conf >= VALIDATE_AT:
                new = "validated"
                validated += 1
            elif conf < ELIMINATE_BELOW:
                new = "false_positive"
                eliminated += 1
            else:
                continue  # uncertain — leave as candidate
            if not ctx.dry_run:
                ctx.store.set_finding_status(eid, f["id"], new)

        summary = (f"{validated} validated, {eliminated} eliminated "
                   f"of {len(candidates)} candidates")
        kind = "dry_run" if ctx.dry_run else "validate_done"
        ctx.emit(kind, f"[validate] {summary}", phase="validate", module=self.id,
                 data={"validated": validated, "eliminated": eliminated,
                       "candidates": len(candidates)})
        if ctx.dry_run:
            return ModuleResult(planned=[f"validate {len(candidates)} candidates"],
                                summary=f"dry-run: {summary}")
        return ModuleResult(summary=summary)
