"""Suite-agnostic ReAct loop. The brain proposes one JSON action per turn; the
executor runs it and returns an observation; repeat until final answer / budget."""
from __future__ import annotations
from dataclasses import dataclass, field
import time

from .actions import Action, parse_action, tool_schema_block


@dataclass
class Observation:
    text: str
    done: bool = False
    success: bool = False


@dataclass
class Episode:
    task_id: str
    solved: bool
    steps: int
    providers: list
    stop_reason: str
    transcript: str
    wall_s: float = 0.0


class Executor:                       # interface; runners subclass
    def tools(self) -> list: raise NotImplementedError
    def system_preamble(self) -> str: return ""
    def run(self, action: Action) -> Observation: raise NotImplementedError


def run_episode(brain, executor, task_id, goal, *, max_steps=20, emit=None):
    emit = emit or (lambda *a, **k: None)
    tools = executor.tools()
    known = {t["name"] for t in tools}
    transcript = (f"{executor.system_preamble()}\n\n{tool_schema_block(tools)}\n\n"
                  f"TASK: {goal}\n")
    providers, malformed = [], 0
    t0 = time.time()
    steps = 0
    for _ in range(max_steps):
        text, provider = brain.think(transcript)
        if provider is None:
            return Episode(task_id, False, steps, providers, "no_reasoner",
                           transcript, time.time() - t0)
        steps += 1
        providers.append(provider)
        action = parse_action(text, known)
        if action is None:
            malformed += 1
            emit("bench_malformed", f"step {steps}: no valid action", "warn")
            if malformed >= 2:
                return Episode(task_id, False, steps, providers, "malformed",
                               transcript, time.time() - t0)
            transcript += ("\nASSISTANT: " + text +
                           "\nSYSTEM: Emit exactly one fenced JSON action.\n")
            continue
        malformed = 0
        transcript += f"\nACTION: {action.tool} {action.args}\n"
        obs = executor.run(action)
        transcript += f"OBSERVATION: {obs.text}\n"
        if obs.done or action.tool == "final_answer":
            return Episode(task_id, bool(obs.success), steps, providers,
                           "final_answer", transcript, time.time() - t0)
    return Episode(task_id, False, steps, providers, "budget", transcript,
                   time.time() - t0)
