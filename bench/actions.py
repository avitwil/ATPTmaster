"""Free-text -> Action. Models emit one JSON action per turn; we take the last
JSON object in the text so trailing prose or a corrected block wins."""
from __future__ import annotations
from dataclasses import dataclass
import json
import re


@dataclass
class Action:
    thought: str
    tool: str
    args: dict


_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _balanced_objects(text: str):
    """Yield substrings that are balanced {...} objects, in order."""
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    yield text[start:i + 1]


def parse_action(text: str, known_tools: set) -> "Action | None":
    text = text or ""
    candidates = _FENCE.findall(text) or list(_balanced_objects(text))
    for raw in reversed(candidates):          # last valid object wins
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        tool = obj.get("tool")
        if tool not in known_tools:
            continue
        args = obj.get("args")
        if not isinstance(args, dict):
            args = {}
        return Action(thought=str(obj.get("thought", "")), tool=tool, args=args)
    return None


def tool_schema_block(tools: list) -> str:
    lines = ["Available tools (emit exactly one as a JSON action):"]
    for t in tools:
        args = ", ".join(t.get("args", []))
        lines.append(f'- {t["name"]}({args}): {t.get("desc","")}')
    lines.append('Respond with one fenced block: ```json {"thought":"...","tool":"<name>","args":{...}} ```')
    return "\n".join(lines)
