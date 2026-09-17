"""Shared helpers for CLI-wrapping modules — binary presence + a never-raising
subprocess runner. Stdlib-only. Keeps tool modules thin and uniform: a missing
tool makes the module no-op cleanly (rc == -1) instead of crashing the engine,
so the framework stays installable on any Kali box regardless of which scanners
are present."""
from __future__ import annotations
import shutil
import subprocess

from . import privilege


def have(binary: str) -> bool:
    return bool(binary) and shutil.which(binary) is not None


def run(argv, timeout: int = 300, sudo: bool = False):
    """Run a scanner. Never raises. Returns (returncode, stdout, stderr).
    rc == -1 → binary missing (caller should no-op); rc == -2 → run error;
    rc == -3 → sudo requested but elevation is not enabled (caller no-ops).

    When sudo=True, the real binary is still presence-checked, then the command
    is prefixed with `sudo -S` (password fed via stdin from privilege, in memory)
    or `sudo -n` (NOPASSWD). The password is never placed in argv."""
    if not argv or not have(argv[0]):
        return -1, "", f"{argv[0] if argv else '(no argv)'} not installed"
    stdin = None
    if sudo:
        prefix, stdin = privilege.sudo_invocation()
        if prefix is None:
            return -3, "", "sudo not enabled (enable it in Settings)"
        argv = list(prefix) + list(argv)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           input=stdin)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:
        return -2, "", str(exc)
