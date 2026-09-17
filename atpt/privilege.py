"""Session-scoped privilege state for sudo elevation.

The sudo password lives ONLY here, in process memory — it is never written to
disk, never logged, and never returned by any HTTP GET. It is set per server run
(re-asked after a restart) and used to feed `sudo -S` over stdin. When elevation
is enabled but no password is set, callers fall back to `sudo -n` (non-interactive),
which succeeds only where the operator's sudoers grants NOPASSWD.

Kept deliberately tiny and dependency-free so it is easy to audit.
"""
from __future__ import annotations

_ALLOWED = False
_PASSWORD: str | None = None   # in-memory only; see module docstring
_ATTACKBOX_PW: dict[str, str] = {}   # eid -> ssh password, in-memory only


def reset() -> None:
    """Forget elevation state (used by tests and on explicit disable)."""
    global _ALLOWED, _PASSWORD
    _ALLOWED = False
    _PASSWORD = None
    _ATTACKBOX_PW.clear()


# --- attack-box SSH password (per engagement, memory only) ------------------
def set_attackbox_password(eid: str, pw: str) -> None:
    if pw:
        _ATTACKBOX_PW[eid] = pw
    else:
        _ATTACKBOX_PW.pop(eid, None)


def has_attackbox_password(eid: str) -> bool:
    return eid in _ATTACKBOX_PW


def set_allowed(allowed: bool) -> None:
    global _ALLOWED
    _ALLOWED = bool(allowed)
    if not _ALLOWED:
        clear_password()


def is_allowed() -> bool:
    return _ALLOWED


def set_password(pw: str) -> None:
    global _PASSWORD
    _PASSWORD = pw or None


def clear_password() -> None:
    global _PASSWORD
    _PASSWORD = None


def has_password() -> bool:
    return _PASSWORD is not None


def current_password() -> str | None:
    """Server-side only accessor for the in-memory sudo password (e.g. to feed
    an install running under sudo -S). Never send this over HTTP."""
    return _PASSWORD


def sudo_invocation() -> tuple[list | None, str | None]:
    """Return (argv_prefix, stdin) for a sudo-elevated command.

    not allowed        -> (None, None)          caller should refuse to elevate
    allowed + password -> (["sudo","-S","-p",""], "<pw>\\n")
    allowed + no pw    -> (["sudo","-n"], None)  NOPASSWD path
    """
    if not _ALLOWED:
        return None, None
    if _PASSWORD is not None:
        return ["sudo", "-S", "-p", ""], _PASSWORD + "\n"
    return ["sudo", "-n"], None
