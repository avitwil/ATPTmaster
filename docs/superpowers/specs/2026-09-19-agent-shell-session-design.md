# Agent Shell-Session Capability — Design

**Date:** 2026-09-19
**Status:** Design (awaiting review)
**Author:** avitwil (with Claude)
**Builds on:** `2026-09-18-llm-driven-offensive-agent-design.md` (Phase 2)

## Problem

The offensive agent (v1) drives **stateless one-shot commands** (curl, nmap, …).
A live run on THM "Infinity Pool" proved it can autonomously find the vulnerability
(command injection in `POST /internal/netcheck`), but it **cannot capture the
flags**, because:

1. The injection is **blind** — no command output is returned, so a flag can't be
   read with a single request.
2. Capturing `user.txt` and especially `root.txt` needs a **held foothold**: an
   interactive session (shell/SSH) where the agent runs many commands, enumerates,
   and privescs — state that must persist across the agent's stateless steps.

Operator goal (explicit): **the app should actually capture the flag, trying every
avenue it can, with engagement scope as the only limit.**

## Goal

Give the agent a **persistent session capability** plus a **full-exploitation
posture**, so it can go foothold → `user.txt` → privesc → `root.txt`, exploring
multiple in-scope attack paths, bounded only by scope.

## Non-goals (YAGNI)

- Not a hostile-process sandbox. Threat model = keep **our own** agent from
  *accidentally* wandering off-scope, not defending against a malicious agent.
- No multi-session orchestration — **one active session at a time**.
- No GUI redesign; reuse Run/Stop, events, findings, report.
- No new reasoning backends.

## Architecture

### A. Session object + lifecycle (`modules/agent_offensive/session.py`)

Module-level state (mirrors `atpt/vpn.py::_STATE`): **one active session**, holding
either a caught reverse-shell socket or an SSH channel. Public interface:

- `start_listener(host, port) -> dict` — bind a reverse-shell listener (see B).
- `catch(timeout) -> dict` — accept one callback; verify the peer IP is in scope;
  return session info or a diagnostic.
- `ssh_connect(host, user, password|key, scope) -> dict` — open an SSH session to
  an **in-scope** host.
- `session_exec(cmd, timeout=60) -> str` — run one command in the held session and
  return its output. Implementation writes `cmd; echo <MARKER>` and reads until the
  unique MARKER, so it knows when output ends (works for both socket and SSH).
- `is_active() -> bool`, `close() -> dict` — teardown (kill listener/socket/ssh).
- `atexit`-registered teardown + called on Stop, like the VPN.

Never raises; all failures become diagnostic strings the agent reads as observations.

### B. Reverse shell (listener bound to tun0 only)

- Listener binds the **VPN interface only** (`192.168.141.21`, discovered from the
  active tun; never `0.0.0.0`), on an operator/config port range.
- The agent triggers the reverse shell through the exploitation it already does —
  a normal `{command: curl … payload …}` whose payload calls back to
  `tun0:<port>`. No special "trigger" action is needed; the listener catches it.
- On accept: **verify the peer IP is in scope** (`scope.in_scope`); if not, drop the
  connection and log. Upgrade to a PTY (`python3 -c 'pty.spawn…'` / `stty`), set a
  stable prompt marker for `session_exec`.

### C. SSH (found/cracked creds)

- `ssh_connect` opens a session to an **in-scope** host (fail-closed if the host is
  out of scope). Password comes from the in-memory `privilege` store (never disk),
  reusing the existing attack-box password mechanism; key path optional.
- Implemented with stdlib (`subprocess` driving `ssh` with `BatchMode`/`sshpass`-free
  password on a PTY) to keep `atpt/` stdlib-only; the module may use a thin helper.

### D. Action grammar (small addition to the loop)

Alongside today's `{command:[argv]}`, the agent may emit:

- `{listen: {port: <int>}}` — arm the reverse-shell listener.
- `{session: "shell command"}` — run a command in the held session.
- `{ssh: {host, user}}` — open an SSH session (password pulled from memory if set).

Parsed by an extended `actions.parse_action` into a typed `Action`. Unknown/empty →
non-fatal "reply with a valid action" observation (existing behavior).

### E. Scope model

Two gates, both deterministic-first with LLM judgment on top (never LLM-alone):

1. **External commands** (`{command}`): unchanged — `ScopeGuard` vets the *connect
   target* (URL/host), which the live-run fix already made correct.
2. **Session endpoint**: verified in-scope at creation (reverse-shell peer IP / SSH
   host must pass `scope.in_scope`; fail-closed).
3. **Session commands** (`{session}`): **all local activity is allowed** (`id`,
   `cat`, `sudo -l`, SUID hunt, privesc, reading flags). The **only** block is an
   outbound connection whose **destination is out of scope** — a pivot to an
   unauthorized host (`ssh 10.9.9.9`, `curl http://external`). A destination that is
   in scope (the target, `localhost`, `127.0.0.1`, the box's own IP, any in-scope
   host) is allowed. Best-effort deterministic scan of the command for host/IP
   references not in scope + the LLM scope-manager. On a single-host CTF this never
   fires — every post-ex command is in scope.

### F. Full-exploitation posture ("all in-scope ways")

- **Broad tool latitude:** the agent's allowlist for a flag-capture engagement
  includes the offensive toolset — `sqlmap`, `hydra`, `nc`/`ncat`, `nmap` (with NSE),
  plus the read-only default. Still every command passes the scope wall; write/egress
  and proxy-redirect flags stay denied. `nc`/`ncat` are needed for shells; they are
  allowed to connect only to in-scope destinations (the wall already enforces this).
- **Persistence / multi-path:** the loop prompt instructs the agent to try
  alternative vectors on a dead end (web → auth/creds → service exploit → foothold →
  privesc), not to quit early. Larger default `max_steps` for this mode.
- **Findings:** a captured flag and each confirmed vuln are recorded as findings
  (not just assets), so they land in the UI and the PTES report.

### G. Listener / session safety

- Listener on `tun0` only, single connection, closed after catch or on teardown.
- Session teardown on Stop and via `atexit` (kills the shell/ssh/listener).
- Flag detection: `session_exec` output (and command output) is scanned for
  `flag{…}` / `THM{…}` / 32-hex; a hit is recorded as a **finding** and surfaced
  immediately.

## Data flow

`{command}` → external tool → assets. `{listen}`/`{ssh}` → session established.
`{session}` → output → observation (feeds next step) + flag/finding harvest. Findings
& assets persist via the engine → map/validate/report unchanged.

## Error handling

- Listener bind fails / no callback within timeout → diagnostic observation; agent
  can retry a different port or payload (non-fatal).
- Session command timeout → observation, session kept if still alive.
- Session dies mid-run → marked inactive; agent can re-establish (non-fatal).
- Reasoner failure → existing retry/`no_reasoner` handling.

## Testing (no real network)

Fake socket + fake SSH doubles injected like `toolwrap.run` is today:

- `session_exec` writes `cmd; echo MARKER` and returns output up to the marker.
- Listener rejects an out-of-scope peer IP; accepts an in-scope one.
- `ssh_connect` refuses an out-of-scope host (fail-closed).
- Session-command scope: `cat /root/root.txt` allowed; `ssh 10.9.9.9` (out-of-scope
  destination) blocked; `curl http://<in-scope>/` allowed.
- Action parsing: `{listen}`, `{session}`, `{ssh}`, `{command}` round-trip.
- Loop: `command` (trigger) → `listen`/session established → `session` runs → flag
  string in output becomes a finding.
- Teardown closes the socket/listener; `atexit` registered once.

## Rollout

Ships behind the same `config.offensive_agent` opt-in. The session capability and the
broad allowlist are only active for engagements that enable the agent; the classic
pipeline and other engagements are untouched.

## Open for the implementation-plan stage

- Exact reverse-shell PTY-upgrade sequence and the `session_exec` marker protocol.
- The session-command host-reference scanner (a small, tested tokenizer).
- Default `max_steps` / port range for flag-capture mode.
- Prompt templates (executor + scope-manager) kept in the module folder.
