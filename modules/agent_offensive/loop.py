"""The ReAct loop: propose -> vet -> (run) -> observe -> propose. Handles four
action kinds — external command, arm listener, run in the held session, SSH.
Blocks and failures are non-fatal observations the model reacts to. Captured
flags become findings. Pure orchestration; side effects are injected or reached
through the session module."""
from __future__ import annotations
import re

from .actions import parse_action
from .guard import session_scope_ok
from . import session as sess

_FLAG = re.compile(r"(?:flag|thm)\{[^}]{1,160}\}", re.IGNORECASE)

_PROMPT = (
    "You are an authorized penetration-testing agent working strictly within the "
    "engagement scope. Goal: {goal}\n\n"
    "Reply with ONE JSON action:\n"
    '  {{"command": ["bin","arg",...], "rationale": "..."}}  run a local recon/exploit tool\n'
    '  {{"listen": {{"port": 4444}}, "rationale": "..."}}      arm a reverse-shell listener (returns host:port)\n'
    '  {{"session": "id", "rationale": "..."}}                run a command in the caught shell\n'
    '  {{"ssh": {{"host":"h","user":"u"}}}}                     open an SSH session (if you have creds)\n'
    '  {{"done": true}}                                         only when BOTH flags are captured\n\n'
    "Strategy: enumerate -> find a vulnerability -> get a foothold (arm a listener, "
    "then trigger a reverse shell back to its host:port via your exploit) -> in the "
    "session read the user flag, enumerate privesc (sudo -l, SUID, cron, caps), "
    "escalate, read the root flag. If something is blocked or fails, try a DIFFERENT "
    "in-scope approach — do not give up. Persist until both flags are found.\n"
    "Tips: BACKGROUND your reverse-shell payload (append ' &') so the triggering "
    "request returns immediately. After triggering, use a session action; the "
    "callback may take a moment. Prefer a python3/bash TCP reverse shell.\n\n"
    "Transcript so far:\n{transcript}\n")


def _scan_flags(text, source, findings, emit):
    for flag in set(_FLAG.findall(text or "")):
        findings.append({"title": f"Flag captured: {flag}", "severity": "critical",
                         "status": "validated", "domain": "Flag",
                         "evidence": {"flag": flag, "via": source}})
        emit("agent_flag", f"[agent] 🚩 FLAG: {flag}  (via {source})", data={"flag": flag})


def run_loop(*, goal, guard, reason_fn, max_steps, emit, execute_fn, harvest_fn,
             scope=None, halt_fn=lambda: False):
    scope = scope or {}
    assets, findings, transcript = [], [], []
    reasoner_failures = 0
    for step in range(1, max_steps + 1):
        if halt_fn():
            break
        text = reason_fn(_PROMPT.format(goal=goal, transcript="\n".join(transcript[-24:])))
        if not text:
            reasoner_failures += 1
            if reasoner_failures >= 2:
                return assets, findings, "agent_no_reasoner: reasoning ladder returned nothing"
            continue
        reasoner_failures = 0
        action = parse_action(text)
        if action is None:
            transcript.append("OBSERVATION: could not parse an action; reply with ONE JSON action.")
            continue

        if action.kind == "done":
            return assets, findings, f"done: {action.rationale or 'goal met'}"

        if action.kind == "listen":
            r = sess.start_listener(action.port or 0, scope=scope)
            if r.get("ok"):
                emit("agent_listen", f"[agent] listener up on {r['listen']}")
                transcript.append(
                    f"OBSERVATION: listener READY on {r['listen']}. Trigger a reverse "
                    f"shell to THIS host:port from the target via your exploit, then run "
                    f"a session command.")
            else:
                transcript.append(f"OBSERVATION: listener failed: {r.get('error')}")
            continue

        if action.kind == "session":
            if not sess.is_active():
                sess.wait_caught(4)
            if not sess.is_active():
                transcript.append("OBSERVATION: no active session yet — arm a listener and "
                                  "trigger a reverse shell first (or the callback hasn't arrived).")
                continue
            ok, reason = session_scope_ok(action.session_cmd, scope)
            if not ok:
                emit("agent_blocked", f"[agent] session blocked: {reason}", level="warn")
                transcript.append(f"BLOCKED: {reason}. Stay on the in-scope target.")
                continue
            if halt_fn():
                break
            emit("agent_session", f"[agent] session$ {action.session_cmd}",
                 data={"rationale": action.rationale})
            out = sess.session_exec(action.session_cmd, timeout=45)
            _scan_flags(out, f"session:{action.session_cmd}", findings, emit)
            transcript.append(f"SESSION$ {action.session_cmd}\n{out[:1600]}")
            continue

        if action.kind == "ssh":
            transcript.append("OBSERVATION: SSH sessions aren't wired yet — get a foothold "
                              "with a reverse shell instead (arm a listener + trigger a callback).")
            continue

        # kind == command
        verdict = guard.vet(action.argv)
        if verdict.blocked:
            emit("agent_blocked", f"[agent] blocked: {verdict.reason} :: {' '.join(action.argv)}",
                 level="warn")
            transcript.append(f"BLOCKED: {verdict.reason}. Propose a different in-scope action.")
            continue
        if halt_fn():
            break
        emit("agent_step", f"[agent] run: {' '.join(action.argv)}", data={"rationale": action.rationale})
        result = execute_fn(action.argv)
        new_assets, new_findings = harvest_fn(action.argv, result)
        assets += new_assets
        findings += new_findings
        blob = (result.get("out", "") or "") + (result.get("err", "") or "")
        _scan_flags(blob, " ".join(action.argv), findings, emit)
        transcript.append(f"RAN: {' '.join(action.argv)} (rc={result.get('rc')})\n"
                          f"OBSERVATION: {blob[:1600]}")

    if halt_fn():
        return assets, findings, "stopped by operator between steps"
    return assets, findings, f"step budget reached ({max_steps} steps)"
