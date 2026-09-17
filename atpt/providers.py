"""Curated registry of subscription-based LLM CLIs the console can install and
log in on the operator's behalf — autonomously.

Pressing "Install" in the UI runs the whole plan: it picks the exact package
from this registry (never typed by the user), installs any missing dependency
(Node.js + npm) first, then does the global install — every privileged step
under `sudo -S`, fed the operator's sudo password over stdin (held in memory
only, never on disk, never in argv). The only thing the user is asked for is
that sudo password.

The reasoning command for a CLI provider is the RESOLVED binary path plus its
args (e.g. `/usr/bin/claude -p`), so runs don't depend on the caller's PATH.

Package names reflect each tool's currently documented npm distribution.
"""
from __future__ import annotations
import shutil
import subprocess

from . import privilege

REGISTRY: dict[str, dict] = {
    "claude": {
        "label": "Claude Code (Anthropic)",
        "binary": "claude",
        "args": ["-p"],                                  # prompt mode
        "pkg": "@anthropic-ai/claude-code",
        "login": ["claude"],
        "login_interactive": True,
        "help": "After install, run `claude` and use /login (opens a browser).",
    },
    "gemini": {
        "label": "Gemini CLI (Google)",
        "binary": "gemini",
        "args": ["-p"],
        "pkg": "@google/gemini-cli",
        "login": ["gemini"],
        "login_interactive": True,
        "help": "After install, run `gemini` and follow the Google sign-in prompt.",
    },
    "codex": {
        "label": "Codex CLI (OpenAI)",
        "binary": "codex",
        "args": ["exec"],                                # non-interactive exec
        "pkg": "@openai/codex",
        "login": ["codex", "login"],
        "login_interactive": False,
        "help": "After install, run `codex login` to authenticate.",
    },
}

# Dependency shared by all npm-distributed CLIs.
_NODE_DEP = {"binary": "npm", "desc": "install Node.js + npm",
            "argv": ["apt-get", "install", "-y", "nodejs", "npm"], "sudo": True}


def known() -> list[str]:
    return list(REGISTRY)


def get(name: str) -> dict | None:
    return REGISTRY.get(name)


def resolved_cmd(name: str) -> str | None:
    """`<resolved bin path> <args>` for a provider (falls back to the bare binary
    name when it isn't on PATH yet). This is what the `cli` reasoning backend runs."""
    e = REGISTRY.get(name)
    if not e:
        return None
    path = shutil.which(e["binary"]) or e["binary"]
    return " ".join([path, *e.get("args", [])]).strip()


def status(name_or_binary: str) -> dict:
    entry = REGISTRY.get(name_or_binary)
    binary = entry["binary"] if entry else (name_or_binary or "").split()[0] if name_or_binary else ""
    path = shutil.which(binary) if binary else None
    return {
        "known": entry is not None,
        "binary": binary,
        "installed": path is not None,
        "path": path,
        "label": entry["label"] if entry else name_or_binary,
        "cmd": resolved_cmd(name_or_binary) if entry else None,
        "help": entry["help"] if entry else None,
    }


def login_argv(name: str) -> list | None:
    entry = REGISTRY.get(name)
    return list(entry["login"]) if entry else None


def install_steps(name: str) -> list | None:
    """Ordered steps to install `name`, computed from current system state.
    `None` for an unknown provider; `[]` when it is already installed."""
    entry = REGISTRY.get(name)
    if not entry:
        return None
    if shutil.which(entry["binary"]):
        return []
    steps = []
    if shutil.which("npm") is None:                      # dependency first
        steps.append(dict(_NODE_DEP))
    steps.append({"binary": entry["binary"], "desc": f"install {entry['binary']}",
                  "argv": ["npm", "install", "-g", entry["pkg"]], "sudo": True})
    return steps


def needs_sudo(name: str) -> bool:
    steps = install_steps(name) or []
    return any(s.get("sudo") for s in steps)


def _run(argv, pw, timeout=900):
    """Run one step. Privileged steps go through `sudo -S` (password on stdin) or
    `sudo -n` when no password is set (NOPASSWD). Password never enters argv."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _sudo_run(argv, pw, timeout=900):
    if pw:
        full = ["sudo", "-S", "-p", "", *argv]
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout, input=pw + "\n")
    else:
        full = ["sudo", "-n", *argv]
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def run_install(name: str, sudo_password: str | None = None) -> dict:
    """Autonomously install `name` and its dependencies. Returns a result dict:
      {ok, log, cmd, status}                     on completion
      {needs_sudo: True}                         when a sudo password is required
      {ok: False, error/failed, ...}             on failure
    Never raises."""
    entry = REGISTRY.get(name)
    if not entry:
        return {"ok": False, "error": f"unknown provider '{name}'"}
    steps = install_steps(name)
    if steps == []:
        return {"ok": True, "already": True, "log": f"{entry['binary']} already installed",
                "cmd": resolved_cmd(name), "status": status(name)}

    pw = sudo_password or privilege.current_password()
    if any(s.get("sudo") for s in steps) and not pw:
        return {"ok": False, "needs_sudo": True}

    log = []
    # Refresh apt indexes before installing the Node dependency.
    if any(s["argv"][0] == "apt-get" for s in steps):
        rc, out, err = _sudo_run(["apt-get", "update", "-y"], pw)
        log.append(f"$ apt-get update -y\n(exit {rc})")
        # non-fatal: continue even if update partially fails

    for s in steps:
        try:
            if s.get("sudo"):
                rc, out, err = _sudo_run(s["argv"], pw)
            else:
                rc, out, err = _run(s["argv"], pw)
        except Exception as exc:
            return {"ok": False, "failed": s["desc"], "log": "\n".join(log + [str(exc)]),
                    "status": status(name)}
        tail = (out or "")[-500:] + (("\n" + err[-500:]) if err else "")
        log.append(f"$ {s['desc']}: {' '.join(s['argv'])}\n(exit {rc}) {tail}".rstrip())
        if rc != 0:
            hint = ""
            if "incorrect password" in (err or "").lower() or "sorry, try again" in (err or "").lower():
                hint = " — sudo password rejected"
            return {"ok": False, "failed": s["desc"] + hint, "log": "\n".join(log),
                    "status": status(name)}

    ok = shutil.which(entry["binary"]) is not None
    return {"ok": ok, "log": "\n".join(log), "cmd": resolved_cmd(name), "status": status(name)}
