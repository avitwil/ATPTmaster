"""Live model discovery: ask a configured provider which models it offers.

Reads the provider's own connection config (backend + api + endpoint + key) and
queries its list endpoint — OpenAI-style `/v1/models`, Anthropic `/v1/models`, or
Ollama `/api/tags`. Keys come from the stored `api_key` or the named env var, and
are used only to make the request (never returned). Stdlib-only; never raises.
"""
from __future__ import annotations
import json
import os
import urllib.request


def _get_json(url: str, headers: dict, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _key(cfg: dict) -> str | None:
    return cfg.get("api_key") or (os.environ.get(cfg["key_env"]) if cfg.get("key_env") else None)


def _openai_models_url(endpoint: str | None) -> str:
    if endpoint and "/chat/completions" in endpoint:
        return endpoint.replace("/chat/completions", "/models")
    return "https://api.openai.com/v1/models"


def _ollama_tags_url(endpoint: str | None) -> str:
    if endpoint and "/api/generate" in endpoint:
        return endpoint.replace("/api/generate", "/api/tags")
    return "http://localhost:11434/api/tags"


def list_models(cfg: dict) -> tuple[list, str | None]:
    """Return (model_ids, error). error is None on success."""
    backend = (cfg or {}).get("backend")
    try:
        if backend == "ollama":
            data = _get_json(_ollama_tags_url(cfg.get("endpoint")), {})
            return [m.get("name") for m in data.get("models", []) if m.get("name")], None
        if backend == "http_api":
            api = (cfg.get("api") or "openai").lower()
            key = _key(cfg)
            if api == "anthropic":
                if not key:
                    return [], "no API key configured for this provider"
                url = cfg.get("models_endpoint") or "https://api.anthropic.com/v1/models"
                headers = {"x-api-key": key,
                           "anthropic-version": cfg.get("anthropic_version", "2023-06-01")}
                data = _get_json(url, headers)
                return [m.get("id") for m in data.get("data", []) if m.get("id")], None
            # openai-compatible
            url = _openai_models_url(cfg.get("endpoint"))
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            data = _get_json(url, headers)
            return [m.get("id") for m in data.get("data", []) if m.get("id")], None
        if backend == "cli":
            return [], "CLI providers don't expose a model list"
    except Exception as exc:
        return [], str(exc)
    return [], f"unknown backend '{backend}'"
