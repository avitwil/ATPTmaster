"""Distill a SUCCESSFUL trajectory into a reusable skill. One reasoning call
summarises the winning steps into a skill JSON; then we deterministically replace
target-specific values (the concrete target host/URL, listener host:port) with
placeholders so the skill applies to a new box. Best-effort — returns None if the
model yields nothing usable. Safety is unchanged: a saved skill only SUGGESTS
commands, each still vetted by ScopeGuard when reused."""
from __future__ import annotations
import time

from .actions import last_json

_PROMPT = (
    "You are distilling a SUCCESSFUL penetration-testing session into a reusable "
    "skill for FUTURE targets. The goal was: {goal}\n\n"
    "From the transcript below, extract the MINIMAL ordered sequence of commands "
    "that actually led to success. Omit failed detours and dead ends. Reply with "
    "ONE JSON object and nothing else:\n"
    '{{"name":"short-kebab-name",'
    '"applies_to":{{"goal_tags":["keyword",...],"service_tags":["http","ssh",...]}},'
    '"steps":[{{"command":["bin","arg",...],"note":"why this step"}}],'
    '"success_note":"one line describing what worked"}}\n'
    "Set service_tags to the services the target actually exposed. Keep commands "
    "generic where you can. Use the argv array form for every command.\n\n"
    "Transcript:\n{transcript}\n")


def _templatise(tok: str, subs: dict) -> str:
    for concrete, placeholder in (subs or {}).items():
        if concrete:
            tok = tok.replace(concrete, placeholder)
    return tok


def distill(*, goal, transcript, reason_fn, substitutions=None, provenance=None):
    text = reason_fn(_PROMPT.format(goal=goal, transcript=transcript))
    obj = last_json(text or "")
    if not isinstance(obj, dict) or not obj.get("steps"):
        return None
    for step in obj["steps"]:
        cmd = step.get("command")
        if isinstance(cmd, list):
            step["command"] = [_templatise(str(tok), substitutions) for tok in cmd]
    obj["provenance"] = provenance or {}
    obj.setdefault("success_note", "")
    obj["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return obj
