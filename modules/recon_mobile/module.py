"""Static APK analysis (mobile). Flags exported Android components — an attack
surface (OWASP Mobile M1/M8). Reads a supplied AndroidManifest.xml
(`config.mobile.manifest`) directly, or decodes an APK with apktool
(`config.mobile.apk`) and reads the manifest from the output. No-op if neither
is available. Non-intrusive (static). Covers the Mobile domain of the scope."""
from __future__ import annotations
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from atpt.module import Module, ModuleResult
from atpt import toolwrap

_ANDROID = "{http://schemas.android.com/apk/res/android}"


def parse_manifest(xml_text: str) -> list[dict]:
    out = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for tag in ("activity", "service", "receiver", "provider"):
        for el in root.iter(tag):
            if (el.get(_ANDROID + "exported") or el.get("exported") or "").lower() == "true":
                name = el.get(_ANDROID + "name") or el.get("name") or "(unnamed)"
                out.append({
                    "domain": "Mobile", "owasp": "M1", "status": "candidate",
                    "source_tool": "apktool",
                    "title": f"Exported {tag}: {name}",
                    "severity": "medium", "cvss": 5.5,
                    "evidence": {"component_type": tag, "name": name, "source": "AndroidManifest.xml"}})
    return out


class ReconMobile(Module):
    def run(self, ctx) -> ModuleResult:
        cfg = json.loads(ctx.engagement.get("config") or "{}").get("mobile", {})
        manifest_path, apk = cfg.get("manifest"), cfg.get("apk")
        if not manifest_path and not apk:
            return ModuleResult(summary="no APK/manifest configured; skipped")
        if ctx.dry_run:
            ctx.emit("dry_run", "[mobile] would statically analyze APK/manifest",
                     phase="recon", module=self.id)
            return ModuleResult(planned=["apktool decode + manifest scan"],
                                summary="dry-run: would analyze APK/manifest")

        xml_text = None
        if manifest_path:
            try:
                xml_text = Path(manifest_path).read_text(errors="replace")
            except OSError:
                xml_text = None
        elif apk:
            outdir = Path(ctx.project_dir) / "var" / "apk" / Path(apk).stem
            rc, _out, _err = toolwrap.run(["apktool", "d", "-f", "-o", str(outdir), apk],
                                          timeout=cfg.get("timeout", 600))
            if rc == -1:
                ctx.emit("apktool_absent", "[mobile] apktool not installed — skipping", "warn",
                         phase="recon", module=self.id)
                return ModuleResult(summary="apktool not installed; skipped")
            mf = outdir / "AndroidManifest.xml"
            if mf.exists():
                xml_text = mf.read_text(errors="replace")
        if not xml_text:
            return ModuleResult(summary="no manifest to analyze; skipped")

        findings = parse_manifest(xml_text)
        ctx.emit("mobile_done", f"[mobile] {len(findings)} exported components",
                 phase="recon", module=self.id, data={"findings": len(findings)})
        return ModuleResult(findings=findings, summary=f"{len(findings)} exported components flagged")
