"""Provider ladder: try registered reasoning providers in preference order,
falling back to the next on refusal or error. Stdlib-only.

A refusal ADVANCES the ladder to the next provider (ultimately a local model the
operator runs themselves) — we never rewrite a prompt to defeat a model's
guardrails. Exhaustion returns None so callers fall back to deterministic logic.
"""
from __future__ import annotations
from dataclasses import dataclass

REFUSAL_MARKERS = (
    "i can't help", "i cannot help", "i can't assist", "i cannot assist",
    "i'm unable to", "i am unable to", "i won't", "i will not",
    "against my guidelines", "cannot comply", "can't comply",
)


def _is_refusal(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    return any(m in t for m in REFUSAL_MARKERS)


# Real backends are registered in Task 3. Tests monkeypatch this dict.
BACKENDS: dict = {}


@dataclass
class ReasoningResult:
    text: str
    provider: str
    status: str = "ok"


class ReasoningLadder:
    def __init__(self, config: dict | None, emit=None):
        cfg = config or {}
        self.providers: dict = cfg.get("providers", {})
        self.preference: list = cfg.get("preference", [])
        self.policy: dict = cfg.get("policy", {})
        self._emit = emit or (lambda *a, **k: None)

    def _allowed(self, provider_cfg: dict, phase: str) -> bool:
        pol = self.policy.get(phase, "any")
        if pol == "local_only":
            return provider_cfg.get("backend") == "ollama"
        return True  # "any" / "hosted_ok" / unknown -> permit

    def reason(self, prompt: str, phase: str) -> "ReasoningResult | None":
        for name in self.preference:
            pc = self.providers.get(name)
            if not pc or not self._allowed(pc, phase):
                continue
            backend = BACKENDS.get(pc.get("backend"))
            if backend is None:
                continue
            try:
                text = backend(pc, prompt)
            except Exception as exc:
                self._emit("reasoning_error", f"provider '{name}' error: {exc}", "warn")
                continue
            if _is_refusal(text):
                self._emit("reasoning_refused", f"provider '{name}' refused; advancing", "info")
                continue
            return ReasoningResult(text=text, provider=name)
        return None
