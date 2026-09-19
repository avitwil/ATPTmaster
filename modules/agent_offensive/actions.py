"""Parse the model's step output into a structured Action. Mirrors the robust
last-JSON-object strategy proven in bench/actions.py. Action kinds:

  command : run an external tool  -> {"command": ["nmap","-Pn","h"], ...}
  listen  : arm the reverse-shell listener -> {"listen": {"port": 4444}}  (port optional)
  session : run a command in the held shell -> {"session": "sudo -l"}
  ssh     : open an SSH session -> {"ssh": {"host": "h", "user": "u"}}
  finding : author a rich finding -> {"finding": {"title": "...", "severity": "high", ...}}
  done    : goal met -> {"done": true}
"""
from __future__ import annotations
import json
import shlex
from dataclasses import dataclass, field


@dataclass
class Action:
    kind: str = "command"                 # command | listen | session | ssh | done
    argv: list[str] = field(default_factory=list)
    session_cmd: str = ""
    port: int = 0
    ssh_host: str = ""
    ssh_user: str = ""
    finding: dict = field(default_factory=dict)
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


def last_json(text: str):
    """The last complete top-level JSON object in the text, or None."""
    obj = None
    for chunk in _iter_json_objects(text or ""):
        try:
            obj = json.loads(chunk)
        except Exception:
            continue
    return obj if isinstance(obj, dict) else None


def parse_action(text: str) -> "Action | None":
    obj = last_json(text)
    if obj is None:
        return None
    rationale = str(obj.get("rationale") or "")
    if obj.get("done"):
        return Action(kind="done", rationale=rationale, done=True)
    if obj.get("session") is not None:
        return Action(kind="session", session_cmd=str(obj.get("session") or ""),
                      rationale=rationale)
    if obj.get("listen") is not None:
        spec = obj.get("listen")
        port = 0
        if isinstance(spec, dict):
            try:
                port = int(spec.get("port") or 0)
            except Exception:
                port = 0
        return Action(kind="listen", port=port, rationale=rationale)
    if obj.get("ssh") is not None:
        spec = obj.get("ssh") or {}
        if isinstance(spec, dict):
            return Action(kind="ssh", ssh_host=str(spec.get("host") or ""),
                          ssh_user=str(spec.get("user") or ""), rationale=rationale)
        return None
    if obj.get("finding") is not None:
        spec = obj.get("finding")
        if isinstance(spec, dict):
            return Action(kind="finding", finding=spec, rationale=rationale)
        return None
    cmd = obj.get("command")
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    elif isinstance(cmd, list):
        argv = [str(x) for x in cmd]
    else:
        return None
    return Action(kind="command", argv=argv, rationale=rationale)
