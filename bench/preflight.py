"""Actionable readiness checks. Each probe returns (ok, detail) and is
monkeypatchable in tests. preflight() composes them into a failure list."""
from __future__ import annotations
import json
import shutil
import subprocess
import urllib.request

USERMOD_HINT = ("Docker socket not usable — run:  "
                "sudo usermod -aG docker $USER && newgrp docker   (detail: {})")


def docker_ok():
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=15)
        return (p.returncode == 0, (p.stderr or p.stdout)[-200:])
    except Exception as exc:
        return (False, str(exc))


def ollama_model_present(model, endpoint="http://localhost:11434/api/tags"):
    try:
        with urllib.request.urlopen(endpoint, timeout=10) as r:
            names = [m.get("name") for m in json.loads(r.read().decode()).get("models", [])]
        return (model in names, "" if model in names else f"have: {names}")
    except Exception as exc:
        return (False, str(exc))


def claude_present():
    path = shutil.which("claude")
    return (path is not None, path or "claude not on PATH")


def docker_compose_v1_present():
    # APB's PentestDriver shells out to the v1 `docker-compose` binary.
    path = shutil.which("docker-compose")
    return (path is not None, path or "docker-compose (v1) not on PATH")


def preflight(suite, *, model, need_docker=True):
    fails = []
    if need_docker:
        ok, detail = docker_ok()
        if not ok:
            fails.append(USERMOD_HINT.format(detail.strip()))
    if suite in ("autopenbench", "both"):
        ok, detail = docker_compose_v1_present()
        if not ok:
            fails.append(f"AutoPenBench needs the v1 'docker-compose' binary: {detail}")
    ok, detail = ollama_model_present(model)
    if not ok:
        fails.append(f"Ollama model '{model}' not available: {detail}")
    ok, detail = claude_present()
    if not ok:
        fails.append(f"Claude CLI missing: {detail}")
    return fails
