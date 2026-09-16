"""Wireless survey — parses an airodump-ng CSV (`config.wireless.csv`) and flags
access points with weak/no encryption (OPEN / WEP) as findings. Live capture
requires operator monitor-mode setup (out of scope for an unattended module), so
this consumes a CSV the operator captured. No-op when none is configured.
Covers the Wireless domain of the scope."""
from __future__ import annotations
import json
from pathlib import Path

from atpt.module import Module, ModuleResult

_WEAK = {"", "OPN", "OPEN", "WEP"}


def parse_airodump(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line.split(",")[0]:   # AP rows start with a BSSID (MAC)
            continue
        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 14:
            continue
        bssid, privacy, essid = cols[0], cols[5], cols[13]
        priv = privacy.upper()
        if priv in _WEAK:
            out.append({
                "domain": "Wireless", "owasp": "A02", "status": "candidate",
                "source_tool": "airodump-ng",
                "title": f"Insecure Wi-Fi ({priv or 'OPEN'}): {essid or bssid}",
                "severity": "high", "cvss": 7.0,
                "evidence": {"bssid": bssid, "essid": essid, "privacy": priv or "OPEN",
                             "source": "airodump-ng"}})
    return out


class ReconWireless(Module):
    def run(self, ctx) -> ModuleResult:
        cfg = json.loads(ctx.engagement.get("config") or "{}").get("wireless", {})
        csv = cfg.get("csv")
        if not csv:
            return ModuleResult(summary="no wireless CSV configured; skipped")
        if ctx.dry_run:
            ctx.emit("dry_run", f"[wireless] would parse {csv}", phase="recon", module=self.id)
            return ModuleResult(planned=[f"parse airodump csv {csv}"],
                                summary="dry-run: would parse airodump CSV")
        try:
            text = Path(csv).read_text(errors="replace")
        except OSError as exc:
            ctx.emit("wireless_error", f"[wireless] cannot read {csv}: {exc}", "warn",
                     phase="recon", module=self.id)
            return ModuleResult(summary=f"wireless CSV unreadable; skipped")
        findings = parse_airodump(text)
        ctx.emit("wireless_done", f"[wireless] {len(findings)} weak APs", phase="recon",
                 module=self.id, data={"findings": len(findings)})
        return ModuleResult(findings=findings, summary=f"{len(findings)} insecure Wi-Fi APs")
