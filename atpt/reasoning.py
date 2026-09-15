"""Provider ladder: try registered reasoning providers in preference order,
falling back to the next on refusal or error. Stdlib-only.

A refusal ADVANCES the ladder to the next provider (ultimately a local model the
operator runs themselves) — we never rewrite a prompt to defeat a model's
guardrails. Exhaustion returns None so callers fall back to deterministic logic.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
import os
import subprocess
import urllib.request

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


def _extract_text(data: dict) -> str:
    if isinstance(data, dict):
        if "response" in data:
            return data["response"] or ""
        if "content" in data:
            c = data["content"]
            if isinstance(c, list) and c and isinstance(c[0], dict):
                return c[0].get("text", "")
            return str(c)
        if data.get("choices"):
            return data["choices"][0].get("message", {}).get("content", "")
    return ""


def _backend_cli(cfg: dict, prompt: str) -> str:
    cmd = cfg.get("cmd")
    if not cmd:
        raise ValueError("cli backend requires 'cmd'")
    proc = subprocess.run(cmd.split() + [prompt], capture_output=True,
                          text=True, timeout=cfg.get("timeout", 120))
    if proc.returncode != 0:
        raise RuntimeError(f"cli exit {proc.returncode}: {proc.stderr[-200:]}")
    return proc.stdout


def _backend_http_api(cfg: dict, prompt: str) -> str:
    """Hosted LLM over HTTP. `api` selects the wire shape so a user connects a
    provider with just api + model + key_env:
      - "anthropic": POST /v1/messages, x-api-key + anthropic-version, messages[]+max_tokens
      - "openai" (default): POST /v1/chat/completions, Bearer, messages[]
    An explicit `endpoint` overrides the default URL (e.g. an OpenAI-compatible gateway).
    """
    key_env = cfg.get("key_env")
    key = os.environ.get(key_env) if key_env else None
    if key_env and not key:
        raise RuntimeError(f"missing API key env var '{key_env}'")
    api = (cfg.get("api") or "openai").lower()
    headers = {"Content-Type": "application/json"}
    if api == "anthropic":
        url = cfg.get("endpoint", "https://api.anthropic.com/v1/messages")
        headers["anthropic-version"] = cfg.get("anthropic_version", "2023-06-01")
        if key:
            headers["x-api-key"] = key
        body = {"model": cfg.get("model"), "max_tokens": cfg.get("max_tokens", 1024),
                "messages": [{"role": "user", "content": prompt}]}
    else:  # openai-compatible (OpenAI, gateways, vLLM, Ollama's /v1, ...)
        url = cfg.get("endpoint", "https://api.openai.com/v1/chat/completions")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": cfg.get("model"), "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 120)) as resp:
        return _extract_text(json.loads(resp.read().decode()))


def _backend_ollama(cfg: dict, prompt: str) -> str:
    url = cfg.get("endpoint", "http://localhost:11434/api/generate")
    body = json.dumps({"model": cfg.get("model", "llama3.1"),
                       "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 300)) as resp:
        return json.loads(resp.read().decode()).get("response", "")


BACKENDS: dict = {"cli": _backend_cli, "http_api": _backend_http_api,
                  "ollama": _backend_ollama}


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
