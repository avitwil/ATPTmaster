"""Extract candidate target hosts from a proposed command's argv, for the scope
wall. Conservative: treats any argv token that looks like a host/IP or a URL as a
target; a token that is purely a flag or a flag's numeric value is not."""
from __future__ import annotations
import re

from atpt.scope import _host_of

_NUM = re.compile(r"^\d+$")


def _looks_like_target(tok: str) -> bool:
    if not tok or tok.startswith("-"):
        return False
    if "://" in tok:
        return True
    if _NUM.match(tok):            # a bare number is a port/count, not a host
        return False
    return bool(re.search(r"[A-Za-z0-9]", tok)) and ("." in tok or ":" in tok)


def extract_targets(argv: list[str]) -> list[str]:
    out, seen = [], set()
    for tok in list(argv)[1:]:
        if not _looks_like_target(tok):
            continue
        h = _host_of(tok)
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out
