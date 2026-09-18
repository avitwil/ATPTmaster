# LLM-Driven Offensive Agent — Design

**Date:** 2026-09-18
**Status:** Design (awaiting review)
**Author:** avitwil (with Claude)

## Problem

Today the pipeline runs a **fixed generic scan chain** (`recon/recon_runner.sh`:
subfinder → naabu → nmap → httpx → ffuf). Two problems observed live against a
TryHackMe box (`10.114.164.13`):

1. **It's brittle.** `naabu -list` hung (70s timeout, 0 ports) on that target, and
   the runner only falls back to a direct `nmap` scan when naabu is *absent* — so
   recon emitted **0 assets**. Plain `nmap -Pn` found 22/ssh + 80/http in 14s.
2. **It doesn't use the LLM.** Every target gets the same canned commands. The
   only LLM-using modules (`map_ptt`, `exploit_hbgpt`) run *after* recon and act on
   discovered assets; with 0 assets they never fire. So "no LLM actions ever."

The application's whole value is an LLM that **chooses what to run per target,
reads the output, and decides the next command** — recon → enumeration → exploit —
instead of a static chain.

## Goal

An **LLM-driven offensive agent** that drives the scan/exploit loop for an
engagement, supervised so it can **never leave scope in any mode**.

Two roles around one ReAct loop:

- **Executor** — the LLM (via the existing `ctx.reason` ladder) proposes one
  command at a time toward the engagement goal.
- **Scope-manager** — vets every proposed command *before* it runs. Two layers:
  - **Deterministic wall** (`atpt/scope.py::in_scope`): the command's target
    host(s) are parsed out; if any is not in scope the command is **blocked, in
    every mode** (`semi` and `full`). Unfoolable — no LLM can override it.
  - **LLM judgment** (on top): flags destructive / off-goal / wandering actions.
    It can *block*, but can never *un-block* what the oracle rejected.

A block or a failure is **non-fatal**: it's fed back to the executor as an
observation, and the executor proposes a different in-scope action.

## Non-goals (YAGNI)

- No replacement of the module/engine architecture; this is one new module.
- No new reasoning backends — reuse the configured ladder (codex → claude →
  deephat) verbatim.
- No autonomous lateral movement / pivoting beyond the engagement's in-scope
  hosts. Out of scope is out of scope.
- No GUI redesign; reuse the existing Run/Stop controls, events feed, findings
  table, and PTES report.
- Not removing the classic recon chain — it stays as the default; the agent is
  opt-in per engagement.

## Reused building blocks (already in the codebase)

| Piece | Role here |
|---|---|
| `atpt/reasoning.py` `ReasoningLadder` / `ctx.reason(prompt, phase)` | Executor + manager LLM calls, with fallback ladder |
| `atpt/scope.py` `in_scope(scope, target)` | The deterministic scope wall (authoritative) |
| `atpt/toolwrap.py` `run(argv, timeout, sudo)` | Never-raising subprocess exec; missing binary = clean no-op |
| `modules/exploit_hbgpt` allow/deny model | Binary allowlist, egress/write denylist, in-scope-target requirement, execution opt-in |
| `bench/agent.py`, `bench/actions.py` (last-JSON parser, ReAct loop) | Reference implementation of the propose→act→observe loop and robust JSON parsing |
| Engine run control (`_start_run` worker, `halt` event) | Step-wise execution, Stop-between-steps, VPN teardown on stop |

## Architecture

### New module: `modules/agent_offensive/`

A standard capability folder (`module.json` + `module.py` with an `AgentOffensive(Module)`
subclass), so the registry picks it up automatically.

- **phase:** `recon` (runs first; its loop spans recon → enumeration → exploit
  internally and emits both assets and findings).
- **intrusive:** `true` (so `semi` mode gates it for approval like any intrusive step).
- **Activation:** runs its loop only when `config.offensive_agent.enabled` is true.
  When disabled it is a clean no-op (`ok=True`, empty result) so the classic chain runs.
- **Mutual exclusion:** when the agent is enabled, the classic intrusive modules
  (`recon_nebula`, `scan_nuclei`, `exploit_sqli`, `exploit_hbgpt`) detect the same
  flag and no-op, so the agent is the sole offensive engine for that run. `map_ptt`
  (enrichment), `validate_xalgorix`, and `report_ptes` continue to run on the
  agent's assets/findings — the downstream pipeline is unchanged.

### The loop (executor)

```
context = {goal, scope summary, allowed tools, transcript}
for step in range(max_steps):
    action = reason(build_prompt(context), phase="exploit")   # -> {command, rationale} JSON
    verdict = scope_manager.vet(action)                       # deterministic wall + LLM judgment
    if verdict.blocked:
        observe(f"BLOCKED: {verdict.reason}")                 # non-fatal; loop continues
        continue
    if mode == "semi" and not approved(action):
        gate_and_wait()                                       # existing approval mechanism
    result = execute(action.command)                          # toolwrap.run, allowlisted
    observe(summarize(result))                                # feeds next step
    extract_assets_and_findings(result)                       # persisted as they appear
    if halt.is_set():                                         # Stop pressed
        break
```

Bounded by `max_steps` (config, default 20). Each step emits an event; discovered
services → assets, confirmed issues → candidate/validated findings, all persisted
incrementally so the UI fills live and a Stop mid-run keeps what was found.

### Scope confirmation gate (first activation)

Before the agent takes **any** action, the scope-manager echoes the **resolved
scope back to the user for a one-time confirmation** — catching typos and
imprecise input (a wrong octet, an unintended CIDR) before a single packet is
sent. This runs in **every mode**, including `full`: full auto removes the
*per-step* human, but this single startup check always happens.

Mechanism (mirrors the existing VPN `needs_sudo` handshake, synchronous at
`/api/run/start`, before any VPN connect or scanning):

1. Compute the **normalized in-scope targets** from the engagement scope
   (`_derive_scope` + `scope.py`), plus a short human-readable summary (the
   in-scope hosts/CIDRs, the explicit out-of-scope entries, and — optionally —
   an LLM one-line restatement of "what I will operate against").
2. If the run has not been confirmed for this exact scope, return
   `{needs_scope_confirm: true, targets: [...], summary: "..."}` — the run does
   **not** start.
3. The UI shows the targets and asks the operator to confirm. On confirm, the
   client re-POSTs with a confirmation carrying a hash of the presented scope
   (so a scope edited in between is re-confirmed, not silently accepted).
4. On confirm → proceed to (VPN connect, then) the loop. On cancel → abort
   cleanly; nothing ran.

This is distinct from per-step approval (`semi`): it is a single gate at start,
about *what* is in scope, not *whether* to run each command.

### The scope-manager

`scope_manager.vet(action)` returns `{blocked: bool, reason: str}`:

1. **Parse targets** from the proposed command (hosts/IPs/URLs in argv).
2. **Deterministic wall:** every parsed target must pass `in_scope(scope, target)`.
   A command with no parseable in-scope target, or any out-of-scope target, is
   **blocked** — regardless of mode. Fail-closed: if targets can't be determined,
   block.
3. **Binary allowlist:** the command's binary must be in the allowed set (below);
   otherwise blocked.
4. **Denylist:** egress/write-flag denylist (reused from `exploit_hbgpt`) blocks
   data-exfil / file-write style flags.
5. **LLM judgment (optional layer):** a `reason(..., phase="scope")` call may add
   a block for destructive/off-goal actions. Advisory-to-block only; never unblocks.

The deterministic steps (1–4) are pure Python and unit-tested without any LLM.

## Command-safety model

- **Default allowlist (read / enumerate):** `nmap`, `curl`, `httpx`, `whatweb`,
  `nikto`, `gobuster`, `ffuf`, `wpscan`, `nuclei`, `dig`, `whois`.
- **Opt-in (exploit / heavier):** `sqlmap`, `hydra`, `nc`, `msfconsole`, … only when
  listed in `config.offensive_agent.allow_bins`. Mirrors the existing
  "execution/allow_bins opt-in" posture of `exploit_hbgpt`.
- **Every command must carry an in-scope target** (enforced by the wall).
- **No raw shell** — the executor emits a structured `{binary, args}` action; args
  are passed as argv (no shell string interpolation), so there's no shell-injection
  surface and target parsing is reliable.

## Configuration (`engagement.config.offensive_agent`)

```json
{
  "offensive_agent": {
    "enabled": true,
    "max_steps": 20,
    "allow_bins": ["sqlmap"],        // extra binaries beyond the read-only default
    "step_timeout": 300
  }
}
```

Absent or `enabled:false` → classic chain runs (fully backward-compatible).

## Data flow

`agent_offensive.run` → per step: `ctx.emit` (event), `store.add_asset` for
discovered services, `store.upsert_finding` for confirmed issues → `map_ptt`
enriches → `validate_xalgorix` promotes/demotes → `report_ptes` renders PTES. No
change to the store schema.

## Error handling

- Reasoner unavailable / returns junk → retry once (reuse the ladder's fallback +
  a last-JSON parse like `bench/actions.py`); if still nothing, end the run with a
  clear `agent_no_reasoner` event (never silently "done").
- Tool failure / timeout → captured as an observation (non-fatal), loop continues.
- Block → observation (non-fatal), loop continues.
- Step budget exhausted → summary event, `ok=True` with whatever was found.

## Mode semantics

| Mode | Startup scope confirmation | Scope wall | Human approval per intrusive step |
|---|---|---|---|
| `semi` | yes | enforced | yes (existing gate) |
| `full` | yes | enforced | no |

Scope wall and the one-time startup scope confirmation are **always** on. `full` =
no human *per-step*, never "no scope wall" and never "skip the startup check."

## Testing plan

All with a **fake reasoner** (scripted actions) and **stubbed `toolwrap.run`** — no
real LLM, no network, no real scanning:

- Deterministic wall: an out-of-scope command is blocked in `full` mode.
- Wall fail-closed: a command with no parseable target is blocked.
- Allowlist: an unlisted binary is blocked; an opt-in binary runs when configured.
- Denylist: an egress/write flag is blocked.
- Loop: block → executor proposes an alternative → in-scope command runs.
- Loop: tool failure → non-fatal → next step runs.
- Step budget stops the loop; partial assets/findings persist.
- Disabled/absent config → module no-ops and the classic chain is untouched.
- Target parsing: hosts/IPs/URLs extracted from representative nmap/curl/sqlmap argv.
- Startup scope confirmation: run does not start until confirmed (all modes,
  including `full`); the returned targets match the normalized scope; a cancel
  aborts with nothing run; a scope changed after presentation forces re-confirm.

## Settled decisions (flagged for review)

1. **Integration = opt-in module, not a replacement.** The agent is a new
   `recon`-phase module gated on `config.offensive_agent.enabled`; the classic chain
   remains the default. Rationale: backward-compatible, reuses map/validate/report,
   smallest blast radius.
2. **Default allowlist is read-only; exploit tools are opt-in.** Matches the
   project's existing fail-closed exploit posture. The user can widen it per
   engagement via `allow_bins`.

## Phase 2 (designed later, built after the core is live-tested): Strategy Toolbox

The agent accumulates experience. When a trajectory *succeeds* (leads to a real
asset/finding), it is distilled into a reusable **skill** and saved to a toolbox;
on a later target the agent searches the toolbox for a skill matching the current
goal and reuses it instead of rediscovering from scratch.

- **A skill** = `{name, applies_to (goal/service tags), steps (templated argv),
  provenance (engagement/finding), success_note}` — persisted (store table or
  files under the data home).
- **Save-on-success:** at end of a run (or when a finding is confirmed), an LLM
  distills the winning steps into a skill; saved skills are operator-visible and
  editable (they are suggestions, not automation).
- **Retrieve:** at loop start / per step, search the toolbox (keyword/tag match,
  stdlib-only — no embeddings) for skills whose `applies_to` fits the goal and the
  discovered services, and inject the top matches into the executor prompt.
- **Safety unchanged:** a skill only *suggests* commands; every command it yields
  still passes the deterministic `ScopeGuard`. A learned skill can never widen
  scope or the allowlist.

This is intentionally deferred: a skill is a distilled *successful* trajectory, so
the core propose→vet→run→observe loop must exist and run first. Phase 2 gets its
own spec section + plan.

## Open for implementation-plan stage

- Exact target-extraction rules per binary (a small, tested parser table).
- Prompt templates for executor and scope-manager (kept in the module folder).
- Whether the LLM-judgment layer ships in v1 or the deterministic wall ships first
  with the LLM layer as a fast follow (both are in scope; sequencing is a plan detail).
