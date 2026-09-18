"""Small config accessors shared across modules."""
from __future__ import annotations
import json


def offensive_agent_on(engagement: dict) -> bool:
    """True when this engagement opts into the LLM offensive agent. When on, the
    classic intrusive modules no-op so the agent is the sole offensive engine."""
    try:
        cfg = json.loads(engagement.get("config") or "{}")
    except Exception:
        return False
    return bool((cfg.get("offensive_agent") or {}).get("enabled"))
