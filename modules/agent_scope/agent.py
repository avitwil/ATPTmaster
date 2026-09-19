"""Scope agent: a plain-chat helper that restates a typed scope for confirmation, or
elicits a scope conversationally and proposes it. Pure prompt/parse logic — the web
layer supplies the reasoner and enforces validation + the deterministic gate."""
from __future__ import annotations
import json
import re

_CONFIRM = (
    "You are a scope agent for an AUTHORIZED penetration test. The operator has ALREADY "
    "defined this scope. Restate it in plain language, flag anything that looks like a "
    "typo or an unintentionally broad range, and ask them to confirm. Do NOT invent new "
    "targets.\n\nScope: {scope}\n\nConversation so far:\n{convo}\n")
_ELICIT = (
    "You are a scope agent for an AUTHORIZED penetration test. The operator has NOT "
    "defined a scope yet. Ask concise questions to establish the in-scope targets "
    "(domains, IPs, CIDRs) and anything explicitly out of scope. When you have enough, "
    "output a line 'PROPOSED_SCOPE: ' followed by a JSON object "
    '{{"in_scope_domains":[...],"in_scope_cidrs":[...],"out_of_scope":[...]}} and ask the '
    "operator to approve. NEVER guess targets they did not give.\n\n"
    "Conversation so far:\n{convo}\n")
_PROP = re.compile(r"PROPOSED_SCOPE:\s*(\{.*\})", re.S)


def build_prompt(typed_scope, convo) -> str:
    body = "\n".join(f"{m.get('role')}: {m.get('text')}" for m in (convo or []))
    if typed_scope:
        return _CONFIRM.format(scope=json.dumps(typed_scope), convo=body)
    return _ELICIT.format(convo=body)


def extract_proposed_scope(text):
    m = _PROP.search(text or "")
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None
