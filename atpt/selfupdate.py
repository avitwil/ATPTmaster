"""Self-update from published *releases* (stable only).

A release is an annotated git tag `vMAJOR.MINOR.PATCH`. A beta / pre-release is a
tag with a suffix (e.g. `v1.2.0-beta.1`) and is IGNORED by the auto-updater — only
stable tags are ever offered or installed. `check()` compares the installed tag to
the latest stable tag on the remote; `apply()` fetches tags and hard-resets the
checkout to that tag, PRESERVING user data (everything under the gitignored `var/`
and `toolbox/` is untouched by the reset) and stashing any stray local edits first,
so the one-click update never asks the user to stash, commit, or delete anything.

Stdlib-only; a running server must be restarted to load the updated code.
"""
from __future__ import annotations
import re
import subprocess
from pathlib import Path

# Stable release tags only. Pre-release tags carry a suffix after the patch
# number (`-beta.1`, `-rc.2`, …) and never match, so they are skipped.
_STABLE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _git(args, cwd, timeout=90):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=timeout)


def _is_repo(project_dir) -> bool:
    return (Path(project_dir) / ".git").exists()


def _semver(tag: str):
    """(major, minor, patch) for a stable tag, else None (pre-release/garbage)."""
    m = _STABLE.match(tag or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _remote_stable_tags(project_dir) -> list[str]:
    """Stable release tags on origin, newest first (`ls-remote` = a network peek,
    no fetch needed). Pre-release tags are filtered out by `_semver`."""
    r = _git(["ls-remote", "--tags", "--refs", "origin", "v*"], project_dir)
    tags = []
    for ln in r.stdout.splitlines():
        parts = ln.split("\t")
        if len(parts) == 2 and parts[1].startswith("refs/tags/"):
            tag = parts[1][len("refs/tags/"):]
            if _semver(tag):
                tags.append(tag)
    return sorted(tags, key=_semver, reverse=True)


def _current_tag(project_dir):
    """The stable release this checkout is on, or None (dev tree / before any tag)."""
    tag = _git(["describe", "--tags", "--abbrev=0", "--match", "v*"], project_dir).stdout.strip()
    return tag or None


def check(project_dir) -> dict:
    if not _is_repo(project_dir):
        return {"repo": False, "error": "not a git checkout — installed from an archive?"}
    try:
        current = _current_tag(project_dir)
        tags = _remote_stable_tags(project_dir)
        if not tags:
            return {"repo": True, "current": current, "latest": None,
                    "update_available": False, "changelog": [],
                    "note": "no stable release published yet"}
        latest = tags[0]
        cur_v, lat_v = _semver(current or ""), _semver(latest)
        update_available = (cur_v is None) or (lat_v > cur_v)
        changelog = []
        if update_available:
            # Best-effort release notes: commit subjects the new tag adds. Needs the
            # objects locally, so fetch tags first (quiet; failure is non-fatal).
            _git(["fetch", "--quiet", "--tags", "origin"], project_dir, timeout=120)
            rng = f"{current}..{latest}" if current else latest
            log = _git(["log", "--no-merges", "--pretty=%h %s", rng], project_dir)
            changelog = [ln for ln in log.stdout.splitlines() if ln.strip()][:50]
        return {"repo": True, "current": current, "latest": latest,
                "update_available": update_available, "changelog": changelog}
    except Exception as exc:
        return {"repo": True, "error": str(exc)}


def apply(project_dir) -> dict:
    """Install the latest stable release. Never blocks on a dirty tree: user data
    (gitignored var/ & toolbox/) is preserved by construction, and any stray local
    edits are stashed as a recoverable backup before the hard-reset to the tag."""
    if not _is_repo(project_dir):
        return {"ok": False, "error": "not a git checkout"}
    try:
        _git(["fetch", "--quiet", "--tags", "origin"], project_dir, timeout=180)
        tags = _remote_stable_tags(project_dir)
        if not tags:
            return {"ok": False, "error": "no stable release to install"}
        latest = tags[0]
        # Back up any local code edits / untracked non-data files so the button
        # never asks the user to resolve anything. Gitignored data is not stashed
        # and not touched by the reset. Harmless if there is nothing to stash.
        _git(["stash", "push", "--include-untracked", "--message", "atpt pre-update backup"],
             project_dir)
        r = _git(["reset", "--hard", latest], project_dir, timeout=180)
        ok = r.returncode == 0
        head = _git(["rev-parse", "--short", "HEAD"], project_dir).stdout.strip()
        return {"ok": ok, "tag": latest, "head": head,
                "output": (r.stdout + r.stderr).strip()[-3000:]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
