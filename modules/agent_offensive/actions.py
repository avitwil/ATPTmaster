"""Parse the model's step output into a structured Action. Mirrors the robust
last-JSON-object strategy proven in bench/actions.py."""
from __future__ import annotations
import json
import shlex
from dataclasses import dataclass, field


@dataclass
class Action:
    argv: list[str] = field(default_factory=list)
    rationale: str = ""
    done: bool = False


def _iter_json_objects(text: str):
    depth, start = 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                yield text[start:i + 1]
                start = None


def parse_action(text: str) -> "Action | None":
    obj = None
    for chunk in _iter_json_objects(text or ""):
        try:
            obj = json.loads(chunk)
        except Exception:
            continue
    if not isinstance(obj, dict):
        return None
    if obj.get("done"):
        return Action(argv=[], rationale=str(obj.get("rationale") or ""), done=True)
    cmd = obj.get("command")
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    elif isinstance(cmd, list):
        argv = [str(x) for x in cmd]
    else:
        return None
    return Action(argv=argv, rationale=str(obj.get("rationale") or ""), done=False)
