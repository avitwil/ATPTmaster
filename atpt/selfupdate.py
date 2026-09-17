"""Self-update helper: check the git checkout against its upstream and pull.

Runs `git` in the project directory. `check()` fetches and compares HEAD to the
tracked upstream, returning a changelog of the commits you'd get. `apply()` does a
fast-forward pull. Stdlib-only, never raises; a running server must be restarted
to load updated code (the UI says so).
"""
from __future__ import annotations
import subprocess
from pathlib import Path


def _git(args, cwd, timeout=90):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=timeout)


def _is_repo(project_dir) -> bool:
    return (Path(project_dir) / ".git").exists()


def check(project_dir) -> dict:
    if not _is_repo(project_dir):
        return {"repo": False, "error": "not a git checkout — installed from an archive?"}
    try:
        branch = (_git(["rev-parse", "--abbrev-ref", "HEAD"], project_dir).stdout.strip() or "main")
        current = _git(["rev-parse", "HEAD"], project_dir).stdout.strip()
        fetch = _git(["fetch", "--quiet", "origin"], project_dir)
        up = _git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
                  project_dir).stdout.strip() or f"origin/{branch}"
        latest = _git(["rev-parse", up], project_dir).stdout.strip()
        log = _git(["log", "--pretty=%h %s (%an, %ar)", f"HEAD..{up}"], project_dir)
        changelog = [ln for ln in log.stdout.splitlines() if ln.strip()]
        return {
            "repo": True, "branch": branch, "upstream": up,
            "current": current[:7], "latest": latest[:7],
            "behind": len(changelog), "changelog": changelog,
            "fetch_error": (fetch.stderr.strip() or None) if fetch.returncode != 0 else None,
        }
    except Exception as exc:
        return {"repo": True, "error": str(exc)}


def apply(project_dir) -> dict:
    if not _is_repo(project_dir):
        return {"ok": False, "error": "not a git checkout"}
    try:
        p = _git(["pull", "--ff-only"], project_dir, timeout=180)
        return {"ok": p.returncode == 0, "output": (p.stdout + p.stderr).strip()[-3000:]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
