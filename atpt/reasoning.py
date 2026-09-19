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

ROLES = ("director", "osint", "active_recon", "skill", "scope", "map", "exploit", "report")


def _is_refusal(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    return any(m in t for m in REFUSAL_MARKERS)


ERROR_MARKERS = (
    "rate limit", "rate-limited", "rate limited", "model unavailable",
    "not available", "not on your plan", "quota", "insufficient_quota",
    "overloaded", "service unavailable", "try again later",
    "flagged for possible cybersecurity risk", "trusted access for cyber",
    "you do not have access", "no access to",
)
_ERR_MAX = 240  # only SHORT responses are judged error-shaped by phrase


def _looks_like_error(text: str) -> bool:
    """True when a process-level success (exit 0 / HTTP 200) actually carried an
    error or unrecognized refusal AS its text. Guarded so a valid long answer — or
    a finding that merely mentions 'rate limit' — is never discarded."""
    t = (text or "").strip()
    if not t:
        return False  # empty is handled by _is_refusal
    try:
        obj = json.loads(t)
        if isinstance(obj, dict) and obj.get("error"):
            return True
    except Exception:
        pass
    if len(t) <= _ERR_MAX and any(m in t.lower() for m in ERROR_MARKERS):
        return True
    return False


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
    argv = cmd.split()
    if cfg.get("model") and cfg.get("model_flag"):   # ladder can pick a CLI model
        argv += [cfg["model_flag"], cfg["model"]]
    proc = subprocess.run(argv + [prompt], capture_output=True,
                          text=True, timeout=cfg.get("timeout", 120))
    if proc.returncode != 0:
        raise RuntimeError(f"cli exit {proc.returncode}: {proc.stderr[-200:]}")
    if not proc.stdout.strip() and proc.stderr.strip():
        raise RuntimeError(f"cli exit 0 but empty stdout; stderr: {proc.stderr[-200:]}")
    return proc.stdout


def _backend_http_api(cfg: dict, prompt: str) -> str:
    """Hosted LLM over HTTP. `api` selects the wire shape so a user connects a
    provider with just api + model + key_env:
      - "anthropic": POST /v1/messages, x-api-key + anthropic-version, messages[]+max_tokens
      - "openai" (default): POST /v1/chat/completions, Bearer, messages[]
    An explicit `endpoint` overrides the default URL (e.g. an OpenAI-compatible gateway).
    """
    # A pasted key (stored in settings) takes precedence; otherwise read from the
    # named environment variable at call time. Keys are never placed in a URL.
    key_env = cfg.get("key_env")
    key = cfg.get("api_key") or (os.environ.get(key_env) if key_env else None)
    if key_env and not cfg.get("api_key") and not key:
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
        effort = cfg.get("effort")
        if effort and effort not in ("", "none"):
            body["reasoning_effort"] = effort
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 120)) as resp:
        data = json.loads(resp.read().decode())
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(f"api error: {str(data['error'])[:200]}")
    return _extract_text(data)


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
        self.ladder: list = cfg.get("ladder") or []   # [{provider, model, effort}]
        self.policy: dict = cfg.get("policy", {})
        self.roles: dict = cfg.get("roles", {}) or {}
        self._emit = emit or (lambda *a, **k: None)

    def _allowed(self, provider_cfg: dict, phase: str, policy: dict) -> bool:
        pol = (policy or {}).get(phase, "any")
        if pol == "local_only":
            return provider_cfg.get("backend") == "ollama"
        return True  # "any" / "hosted_ok" / unknown -> permit

    def _resolve(self, role):
        """Per-role override of the (ladder, preference, policy) triple, falling
        back to the global config when the role is unset, unknown, or malformed."""
        rc = self.roles.get(role) if role else None
        if isinstance(rc, dict):
            return (rc.get("ladder") or [], rc.get("preference") or [],
                    rc.get("policy") or self.policy)
        return self.ladder, self.preference, self.policy

    def _entries(self, ladder, preference):
        """Yield (provider, model_override, effort). Prefer the model-based ladder;
        fall back to the plain provider preference list for older configs."""
        if ladder:
            for e in ladder:
                yield e.get("provider"), e.get("model"), e.get("effort")
        else:
            for name in preference:
                yield name, None, None

    def reason(self, prompt: str, phase: str, role: str | None = None) -> "ReasoningResult | None":
        ladder, preference, policy = self._resolve(role)
        for provider, model, effort in self._entries(ladder, preference):
            pc = self.providers.get(provider)
            if not pc or not self._allowed(pc, phase, policy):
                continue
            backend = BACKENDS.get(pc.get("backend"))
            if backend is None:
                continue
            cfg = dict(pc)                       # per-entry model/effort override
            if model:
                cfg["model"] = model
            if effort:
                cfg["effort"] = effort
            try:
                text = backend(cfg, prompt)
            except Exception as exc:
                self._emit("reasoning_error", f"provider '{provider}' error: {exc}", "warn")
                continue
            if _is_refusal(text):
                self._emit("reasoning_refused", f"provider '{provider}' refused; advancing", "info")
                continue
            if _looks_like_error(text):
                self._emit("reasoning_error",
                           f"provider '{provider}' returned an error-shaped response; advancing",
                           "warn")
                continue
            return ReasoningResult(text=text, provider=provider)
        return None
