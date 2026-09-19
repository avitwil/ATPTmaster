"""Module contract + run context. A capability = one folder under modules/
with a module.json manifest and a Module subclass. Drop a folder in -> it is
registered. This is what makes the system modular and updatable."""
from __future__ import annotations
import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Canonical phase order the engine walks.
PHASES = ["scope", "recon", "map", "exploit", "validate", "post", "report"]


@dataclass
class Manifest:
    id: str
    name: str
    phase: str
    entrypoint: str                       # "module:ClassName" (file:class)
    provides: list[str] = field(default_factory=list)   # tokens it writes
    consumes: list[str] = field(default_factory=list)   # tokens it needs
    intrusive: bool = False               # gates approval in semi/full modes
    run_modes: list[str] = field(default_factory=lambda: ["step", "semi", "full"])
    enabled: bool = True
    extracted_from: str = ""              # provenance: repo@commit
    description: str = ""

    @staticmethod
    def from_file(path: Path) -> "Manifest":
        data = json.loads(Path(path).read_text())
        known = {f.name for f in dataclasses.fields(Manifest)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"{path}: unknown manifest keys {sorted(unknown)}")
        return Manifest(**data)

    def validate(self) -> None:
        if self.phase not in PHASES:
            raise ValueError(f"{self.id}: unknown phase '{self.phase}'")
        for m in self.run_modes:
            if m not in ("step", "semi", "full"):
                raise ValueError(f"{self.id}: unknown run_mode '{m}'")


@dataclass
class ModuleResult:
    assets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    summary: str = ""
    planned: list[str] = field(default_factory=list)   # dry-run: what it WOULD do
    ok: bool = True     # False => the module failed; engine must NOT mark it completed
                        # (else a failed recon is "done" forever and wedges the pipeline)


@dataclass
class RunContext:
    engagement: dict
    scope: dict
    store: Any
    project_dir: Path
    dry_run: bool = False
    reasoner: Any = None
    goals: str = ""            # operator-stated CTF objective, injected into prompts

    def emit(self, kind: str, message: str, level: str = "info",
             phase: str | None = None, module: str | None = None,
             data: dict | None = None) -> None:
        self.store.add_event(self.engagement["id"], phase, module, level, kind, message, data)

    def reason(self, prompt: str, phase: str, role: str | None = None) -> "str | None":
        if self.reasoner is None:
            return None
        if self.goals:
            prompt = f"Engagement goals: {self.goals}\n\n{prompt}"
        res = self.reasoner.reason(prompt, phase, role)
        return res.text if res else None


class Module:
    """Base class. Subclasses override run(); plan() is optional (for step/dry)."""
    def __init__(self, manifest: Manifest, project_dir: Path):
        self.manifest = manifest
        self.project_dir = project_dir

    @property
    def id(self) -> str:
        return self.manifest.id

    def plan(self, ctx: RunContext) -> list[str]:
        return [f"{self.manifest.id}: {self.manifest.name} ({self.manifest.phase})"]

    def run(self, ctx: RunContext) -> ModuleResult:
        raise NotImplementedError(f"{self.manifest.id} has no run()")
