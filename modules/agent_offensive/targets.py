"""Extract the CONNECT target host(s) from a proposed command's argv, for the
scope wall. The target is where the tool actually connects — a URL or a bare
host/IP argument — NOT the value of a payload/header/cookie/auth flag (an
injection payload like `--data host=$(...)` is data sent TO the in-scope host,
not a new target). Conservative and fail-closed: a malformed/payload-ish token
is simply not treated as a target."""
from __future__ import annotations
import re

from atpt.scope import _host_of

_NUM = re.compile(r"^\d+$")
# a real host/IP (v4/v6, optional port/brackets) — rejects payloads with =$;(){} etc.
_HOSTISH = re.compile(r"^[A-Za-z0-9._:\[\]-]+$")

# Flags whose following value is payload / headers / creds / method — never a
# connect target. `-u`/`--user` is curl basic-auth (added only for curl; for
# ffuf/gobuster/nuclei/sqlmap `-u`/`--url` IS the target and is not skipped).
_SKIP_VALUE = frozenset({
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii",
    "-F", "--form", "--form-string", "-H", "--header", "--headers", "-b", "--cookie",
    "-A", "--user-agent", "-e", "--referer", "-X", "--request", "-w", "--wordlist"})
_CURL_SKIP = frozenset({"-u", "--user"})


def _looks_like_target(tok: str) -> bool:
    if not tok or tok.startswith("-"):
        return False
    if "://" in tok:
        return True
    if _NUM.match(tok):            # a bare number is a port/count, not a host
        return False
    return bool(re.search(r"[A-Za-z0-9]", tok)) and ("." in tok or ":" in tok)


def extract_targets(argv: list[str]) -> list[str]:
    skip = set(_SKIP_VALUE)
    if argv and argv[0] == "curl":
        skip |= _CURL_SKIP
    out, seen = [], set()
    toks = list(argv)[1:]
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in skip:                       # flag whose value is not a target
            i += 2
            continue
        if "=" in tok and tok.split("=", 1)[0] in skip:   # inline --data=... form
            i += 1
            continue
        if _looks_like_target(tok):
            h = _host_of(tok)
            # only accept a clean host/IP; payload-ish tokens (=$;(){}) are dropped
            if h and _HOSTISH.match(h) and h not in seen:
                seen.add(h)
                out.append(h)
        i += 1
    return out
