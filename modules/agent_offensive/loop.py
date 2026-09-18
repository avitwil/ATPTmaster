"""The ReAct loop: propose -> vet -> (run) -> observe -> propose. Blocks and tool
failures are non-fatal observations the model reacts to. Pure orchestration; all
side effects are injected (reason_fn, execute_fn, harvest_fn, emit, halt_fn)."""
from __future__ import annotations

from .actions import parse_action

_PROMPT = (
    "You are an authorized penetration-testing agent. Goal: {goal}\n"
    "Allowed to act ONLY within the engagement scope. Propose the SINGLE next "
    "command as JSON: {{\"command\": [\"bin\",\"arg\",...], \"rationale\": \"...\"}} "
    "or {{\"done\": true}} when the goal is met.\n\nTranscript so far:\n{transcript}\n"
)


def run_loop(*, goal, guard, reason_fn, max_steps, emit, execute_fn, harvest_fn,
             halt_fn=lambda: False):
    assets, findings, transcript = [], [], []
    reasoner_failures = 0
    for step in range(1, max_steps + 1):
        if halt_fn():
            return assets, findings, "stopped by operator between steps"
        text = reason_fn(_PROMPT.format(goal=goal, transcript="\n".join(transcript[-20:])))
        if not text:
            reasoner_failures += 1
            if reasoner_failures >= 2:
                return assets, findings, "agent_no_reasoner: reasoning ladder returned nothing"
            continue
        reasoner_failures = 0
        action = parse_action(text)
        if action is None:
            transcript.append("OBSERVATION: could not parse an action; reply with JSON.")
            continue
        if action.done:
            return assets, findings, f"done: {action.rationale or 'goal met'}"
        verdict = guard.vet(action.argv)
        if verdict.blocked:
            emit("agent_blocked", f"[agent] blocked: {verdict.reason} :: {' '.join(action.argv)}",
                 level="warn")
            transcript.append(f"BLOCKED: {verdict.reason}. Propose a different in-scope action.")
            continue
        if halt_fn():
            return assets, findings, "stopped by operator before execution"
        emit("agent_step", f"[agent] run: {' '.join(action.argv)}", data={"rationale": action.rationale})
        result = execute_fn(action.argv)
        new_assets, new_findings = harvest_fn(action.argv, result)
        assets += new_assets
        findings += new_findings
        transcript.append(
            f"RAN: {' '.join(action.argv)} (rc={result.get('rc')})\n"
            f"OBSERVATION: {(result.get('out') or result.get('err') or '')[:1500]}")
    return assets, findings, f"step budget reached ({max_steps} steps)"
