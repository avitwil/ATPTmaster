"""Adapt ATPT's ReasoningLadder to the agent's Brain protocol.
Primary = Opus via the Claude Code CLI; fallback = a local model (DeepHat via
Ollama) or another hosted CLI (Codex). A provider refusal advances the ladder
(ReasoningLadder's own behavior)."""
from __future__ import annotations
import shutil

from atpt.reasoning import ReasoningLadder

DEEPHAT_MODEL = "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M"
CODEX_MODEL = "gpt-5.6-sol"

_PROVIDERS = {
    "opus": lambda claude_path: {
        "backend": "cli",
        "cmd": f"{claude_path or shutil.which('claude') or 'claude'} -p",
        # 300s: large pentest transcripts make `claude -p` slow; 180s timed out
        # mid-run and dropped the whole episode to no_reasoner.
        "model": "opus", "model_flag": "--model", "timeout": 300,
    },
    "deephat": lambda _cp: {
        "backend": "ollama", "model": DEEPHAT_MODEL,
        "endpoint": "http://localhost:11434/api/generate", "timeout": 300,
    },
    # Codex CLI (OpenAI, ChatGPT auth) — a remote fallback with no local GPU
    # load, for machines where running a local Ollama model is not viable.
    "codex": lambda _cp: {
        "backend": "cli",
        "cmd": f"{shutil.which('codex') or 'codex'} exec",
        "model": CODEX_MODEL, "model_flag": "-m", "timeout": 300,
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
