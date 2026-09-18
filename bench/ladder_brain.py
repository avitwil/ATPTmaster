"""Adapt ATPT's ReasoningLadder to the agent's Brain protocol.
Primary = Opus via the Claude Code CLI; fallback = DeepHat via Ollama.
A provider refusal advances the ladder (ReasoningLadder's own behavior)."""
from __future__ import annotations
import shutil

from atpt.reasoning import ReasoningLadder

DEEPHAT_MODEL = "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M"

_PROVIDERS = {
    "opus": lambda claude_path: {
        "backend": "cli",
        "cmd": f"{claude_path or shutil.which('claude') or 'claude'} -p",
        "model": "opus", "model_flag": "--model", "timeout": 180,
    },
    "deephat": lambda _cp: {
        "backend": "ollama", "model": DEEPHAT_MODEL,
        "endpoint": "http://localhost:11434/api/generate", "timeout": 300,
    },
}


def build_config(primary="opus", fallback="deephat", claude_path=None) -> dict:
    order = [p for p in (primary, fallback) if p]
    providers = {name: _PROVIDERS[name](claude_path) for name in order}
    return {"providers": providers,
            "ladder": [{"provider": name} for name in order],
            "policy": {}}


class LadderBrain:
    def __init__(self, config: dict, phase: str = "exploit", emit=None):
        self.ladder = ReasoningLadder(config, emit=emit)
        self.phase = phase

    def think(self, transcript: str):
        result = self.ladder.reason(transcript, self.phase)
        if result is None:
            return "", None
        return result.text, result.provider
