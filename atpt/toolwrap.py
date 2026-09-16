"""Shared helpers for CLI-wrapping modules — binary presence + a never-raising
subprocess runner. Stdlib-only. Keeps tool modules thin and uniform: a missing
tool makes the module no-op cleanly (rc == -1) instead of crashing the engine,
so the framework stays installable on any Kali box regardless of which scanners
are present."""
from __future__ import annotations
import shutil
import subprocess


def have(binary: str) -> bool:
    return bool(binary) and shutil.which(binary) is not None


def run(argv, timeout: int = 300):
    """Run a scanner. Never raises. Returns (returncode, stdout, stderr).
    rc == -1 → binary missing (caller should no-op); rc == -2 → run error."""
    if not argv or not have(argv[0]):
        return -1, "", f"{argv[0] if argv else '(no argv)'} not installed"
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:
        return -2, "", str(exc)
