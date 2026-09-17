"""Curated registry of subscription-based LLM CLIs the console can install and
log in on the operator's behalf.

Only these known CLIs can be auto-installed (we must know the package + login
command). A custom `cli` provider still works — the operator installs it
themselves. Install and login are side-effectful and are ALWAYS gated behind an
explicit click in the UI; the exact command is shown verbatim first.

Install/login command strings reflect each tool's currently documented package
name; verify against the vendor docs if a provider changes its distribution.
"""
from __future__ import annotations
import shutil
import subprocess

REGISTRY: dict[str, dict] = {
    "claude": {
        "label": "Claude Code (Anthropic)",
        "binary": "claude",
        "install": ["npm", "install", "-g", "@anthropic-ai/claude-code"],
        # Claude Code logs in interactively (opens a browser / `/login`).
        "login": ["claude"],
        "login_interactive": True,
        "help": "After install, run `claude` and use /login (opens a browser).",
    },
    "gemini": {
        "label": "Gemini CLI (Google)",
        "binary": "gemini",
        "install": ["npm", "install", "-g", "@google/gemini-cli"],
        "login": ["gemini"],
        "login_interactive": True,
        "help": "After install, run `gemini` and follow the Google sign-in prompt.",
    },
    "codex": {
        "label": "Codex CLI (OpenAI)",
        "binary": "codex",
        "install": ["npm", "install", "-g", "@openai/codex"],
        "login": ["codex", "login"],
        "login_interactive": False,
        "help": "After install, run `codex login` to authenticate with your ChatGPT account.",
    },
}


def known() -> list[str]:
    return list(REGISTRY)


def get(name: str) -> dict | None:
    return REGISTRY.get(name)


def status(name_or_binary: str) -> dict:
    """Presence of a provider. `name_or_binary` may be a registry key, a bare
    binary, or a full command string (first token is treated as the binary)."""
    entry = REGISTRY.get(name_or_binary)
    binary = entry["binary"] if entry else (name_or_binary or "").split()[0] if name_or_binary else ""
    path = shutil.which(binary) if binary else None
    return {
        "known": entry is not None,
        "binary": binary,
        "installed": path is not None,
        "path": path,
        "label": entry["label"] if entry else name_or_binary,
        "install": entry["install"] if entry else None,
        "help": entry["help"] if entry else None,
    }


def login_argv(name: str) -> list | None:
    entry = REGISTRY.get(name)
    return list(entry["login"]) if entry else None


def install(name: str, timeout: int = 600) -> tuple[int, str, str]:
    """Run a known provider's install command. Never raises.
    rc == -1 → unknown provider; other rc from the package manager."""
    entry = REGISTRY.get(name)
    if not entry:
        return -1, "", f"unknown provider '{name}' — install it yourself (custom command)"
    try:
        p = subprocess.run(entry["install"], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:
        return -2, "", str(exc)
