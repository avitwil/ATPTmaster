# LLM as Director + Rich Findings + LLM Report — Design

**Date:** 2026-09-19
**Status:** Design (awaiting review)
**Author:** avitwil (with Claude)

## Problem

The user tested the released **v1.0.0** and set a clear direction: today the app
behaves like *a program that fires scans and exploits automatically*, and the LLM is
a buried opt-in that only enriches the fixed pipeline. It should instead be the
**DIRECTOR of the engagement** — the thing that decides what to do, reads the
output, concludes what is a real issue, and writes it up. Three concrete defects
came out of that test:

- **Bug 1 — the model ladder does not fall back when a provider fails.** A provider
  that succeeds at the process level (exit 0 / HTTP 200) but returns an *error or
  unrecognized refusal as its text* is taken as a valid answer, so the ladder never
  advances. Real cases seen: subscription CLIs / hosted APIs printing
  "model unavailable / rate-limited / not on your plan", and Codex's
  "flagged for possible cybersecurity risk … join Trusted Access for Cyber".
- **Bug 2 — you cannot see a finding's details.** The findings table on the console
  is plain, non-clickable rows; there is no way to open a finding and read its
  write-up or attach a screenshot.
- **Bug 3 — the report is just headlines.** "The report is the core of the app;
  today it's just headlines, no real info from the specific task, no remediations."
  The PTES template is fine — the *data feeding it is thin* (a bare
  "1 asset found"), and nothing is written from the real run.

## Goal

Evolve the existing offensive agent (`modules/agent_offensive/`, a ReAct loop
propose→vet→run→observe) into the **primary engine** of an engagement, give it a
first-class way to **author each finding as its own reasoned conclusion**, persist
those rich findings, surface them in a **clickable detail view with screenshots**,
and have an **LLM write the report** from the real run transcript — with the
deterministic pipeline and template kept as offline fallbacks. Fix the three bugs
as part of the same body of work.

**The LLM gains judgment, not a way around guardrails.** (See Safety, below.)

## Non-goals (YAGNI)

- No new reasoning backends; reuse the configured ladder verbatim.
- No headless-browser / auto-screenshot capture of target pages — screenshots stay
  **operator-attached**; auto-capture is a documented FUTURE add.
- No removal of the fixed pipeline (`recon→map→exploit→validate→report`) or the
  deterministic report template — both become fallbacks / a tool library.
- No change to the ScopeGuard wall, the one-time startup scope-confirmation gate, or
  semi-mode per-step approvals. This work does not touch enforcement.
- No SQL-queryable columns for the new narrative finding fields (see Decision D1) —
  they ride in the existing `evidence` JSON, avoiding a schema migration.
- No per-finding LLM call at report time (latency): findings are authored *during*
  the run; the report adds **one** narrative LLM pass. (A slow/expensive primary —
  e.g. a CLI-driven model at ~75–140s a call — would make N per-finding calls
  unusably slow.)

## Safety (unchanged, non-negotiable)

Every command the agent proposes still passes the deterministic `ScopeGuard`
(`modules/agent_offensive/guard.py`) at execution time; the one-time startup
scope-confirmation gate stays; `semi` mode still approves intrusive steps. None of
the six items below can widen scope, the binary allowlist, or the egress/write
denylist:

- The `finding` action (item 2) records a *conclusion* — it runs no command, so it
  has no execution surface at all.
- The LLM report pass (item 3) only reads persisted events/findings and writes
  prose; it launches nothing.
- Making the director the default engine (item 1) changes *which engine runs*, not
  *what it is allowed to run* — the wall is identical in every mode.
- No guardrail-bypass prompt engineering anywhere; a refusal still advances the
  ladder toward a model the operator hosts themselves.
- Per-role model ladders (item 7) only choose *which model's text comes back* for a
  role; they cannot alter the scope wall, allowlist, denylist, or approvals. Any role
  can be pointed at any provider without affecting enforcement.

## Current state (verified in code, 2026-09-19 @ `5ffae4b`)

| Piece | Today | Relevant to |
|---|---|---|
| `atpt/reasoning.py` `ReasoningLadder.reason()` | Advances only on a backend **exception**, or when `_is_refusal(text)` is true (empty text or a `REFUSAL_MARKERS` phrase). A 200/exit-0 error-as-text is returned as a valid answer. **One ladder is shared by every role**; `phase` only gates `policy` (`local_only`), not provider order. | Items 6, 7 |
| `_backend_cli` | Raises on **non-zero exit**; returns stdout otherwise (an error printed with exit 0 slips through). | Item 6 |
| `_backend_http_api` | `urlopen` raises `HTTPError` on 4xx/5xx (advances); a 200 body carrying `{"error": …}` is parsed and returned as text. | Item 6 |
| `modules/agent_offensive/actions.py` `parse_action` | Kinds: `command` / `listen` / `session` / `ssh` / `done`. No `finding`. | Item 2 |
| `modules/agent_offensive/loop.py` `run_loop` | Findings come only from `_scan_flags` (flag regex) + `harvest_fn`. Returns `(assets, findings, summary)`; `_finish` distills on success. | Items 1, 2 |
| `modules/agent_offensive/module.py` | Opt-in via `config.offensive_agent.enabled`; no-op when off; mutually exclusive with the classic intrusive modules. | Item 1 |
| `atpt/state.py` findings table | Columns: `id, engagement_id, asset_id, title, domain, severity, cvss, owasp, status, evidence, source_tool, created_at`. No description/reproduction/impact/remediation. `upsert_finding` persists exactly those. | Item 4 |
| `atpt/state.py` events | `recent_events(eid, limit=15)` — capped, DESC, omits `data`. No "all events" accessor. | Item 3 |
| `atpt/engine.py` | Builds the `ReasoningLadder` from `config.reasoning` / settings (`_ctx` gives `ctx.reason`); persists `res.findings` via `store.upsert_finding`. | Items 1, 3 |
| `modules/report_ptes/module.py` `build_report_md` | Pure, deterministic. `_load_evidence` parses the `evidence` JSON; "Affected" reads `ev.asset_value`; remediation is an OWASP-keyed default; renders `rc.get("screenshots")` from `config.report.findings[<id>]`. | Items 3, 5 |
| `atpt/web.py` | Findings table (~line 1139) is plain `<tr>` with **no click handler**. `/api/findings` returns rows with parsed evidence. The **report panel already** has a per-finding screenshot slot + "Add screenshot" (`uploadPicked` → `/api/report-settings` → `config.report.findings[<id>].screenshots`). | Items 3, 5 |

---

## Item 1 — Director-as-engine (make the ReAct agent the primary flow)

**What:** The offensive agent becomes the **default** engine for a new engagement;
the fixed pipeline is the explicit fallback and the tool library the director draws
on (same binaries: nmap/nuclei/sqlmap/curl/… via the allowlist).

**How (smallest blast radius, reusing the existing mutual-exclusion wiring):**

- The agent already no-ops when `config.offensive_agent.enabled` is false, and the
  classic intrusive modules already no-op when it is true. So "director as engine" =
  **default the flag on for newly created engagements** and surface the choice
  prominently, rather than adding a new engine dispatcher.
- The web **create-engagement** flow sets `offensive_agent.enabled = true` by default;
  a **visible** engine toggle (console-level, not buried in Settings) lets the
  operator pick "Director (LLM)" (default) vs "Classic pipeline" (fallback).
- **Backward-compatible:** existing engagements keep their stored config untouched;
  only new engagements default to the director. Absent config → whatever the create
  flow wrote.
- The director keeps using the same underlying tools it already runs; we do **not**
  build a bridge that invokes the classic modules step-by-step (YAGNI). The classic
  pipeline remains selectable as a whole-engine fallback.

**Tests:** a new engagement created via the web flow has the director enabled; the
toggle flips it and the classic pipeline runs; an existing engagement's stored
config is not rewritten by the default.

## Item 2 — Per-finding LLM analysis (a first-class `finding` action)

**What:** When the director concludes something is a real issue, it reports a
**structured finding it authored** — not a bare "asset found". This is the substance
that later feeds both the detail view and the report.

**Action shape** (added to the loop's prompt and to `parse_action`):

```json
{"finding": {
   "title": "…",
   "severity": "critical|high|medium|low|info",
   "what_it_is": "plain-language description of the issue",
   "how_i_proved_it": "the actual commands + output / reproduction steps",
   "affected": "the asset (host/URL/param) this is on",
   "impact": "what an attacker gains",
   "remediation": "how to fix it",
   "confidence": "confirmed|likely|tentative",
   "owasp": "A03 (optional)", "cvss": 7.5, "domain": "Web (optional)"
 }, "rationale": "…"}
```

**Loop branch (`modules/agent_offensive/loop.py`):** on a `finding` action, build a
finding dict and append it to `findings`, emit an `agent_finding` event, then
**continue** (the director may author several findings and keep working; the loop
still ends only on `done` / budget / halt). Missing `title` or `severity` →
non-fatal observation asking the model to re-state the finding, `continue`.

The dict maps onto the existing store shape with the narrative fields carried in
`evidence` (see Decision D1):

```python
{
  "title": …, "severity": …, "domain": finding.get("domain") or "General",
  "owasp": …, "cvss": …,
  "status": _status_from_confidence(confidence),   # confirmed→"validated", else "candidate"
  "source_tool": "agent-director",
  "evidence": {
     "asset_value": affected,            # build_report_md already reads ev.asset_value
     "description": what_it_is,
     "reproduction": how_i_proved_it,
     "impact": impact,
     "remediation": remediation,
     "confidence": confidence,
  },
}
```

**Safety net kept:** `_scan_flags` (flag→finding) and `harvest_fn` stay exactly as
they are; substance now comes from the director's authored findings, with the
automatic harvest as a backstop. Captured flags remain `status="validated"`.

**Tests:** `parse_action` returns a `finding` Action from representative JSON; the
loop appends a well-formed finding dict with the narrative fields under `evidence`
and continues; a malformed finding yields a non-fatal observation, not a crash;
`_scan_flags`/`harvest` still fire alongside.

## Item 4 — Findings carry real fields, stored

**What:** The director's analysis must persist so the **same data feeds the detail
view and the report**.

**Decision D1 — carry the narrative fields inside the existing `evidence` JSON, not
new columns.** `upsert_finding` already serializes `evidence` to JSON and
`_load_evidence` already parses it, so this needs **zero schema migration** and is
fully backward-compatible with existing engagement databases. `title`, `severity`,
`status`, `cvss`, `owasp`, `domain` stay first-class columns (they are sorted,
counted, and grouped). The new fields (`description`, `reproduction`, `impact`,
`remediation`, `confidence`) live under `evidence`.

*Rejected alternative:* adding columns. It would force an idempotent
`ALTER TABLE ADD COLUMN` migration (the store runs `CREATE TABLE IF NOT EXISTS`,
which will not alter an existing table), adding risk for no queryability we need.
If SQL-level querying of these fields is ever wanted, that guarded migration is the
documented path.

**Report consumes it:** `build_report_md` renders `evidence.description`,
`evidence.reproduction`, `evidence.impact`, and prefers `evidence.remediation` over
the OWASP-keyed default when present. "Affected" continues to read
`evidence.asset_value`.

**Tests:** a finding round-trips through `upsert_finding` → `list_findings` with the
`evidence` narrative intact; `build_report_md` prints the description / reproduction
/ impact / director remediation for such a finding and still falls back to the
OWASP default when `evidence.remediation` is absent.

## Item 5 — Clickable finding detail + screenshots (Bug 2)

**What:** Findings-table rows become **clickable** → a detail panel shows that
finding's full write-up (description, `how_i_proved_it`/reproduction, impact,
director remediation, confidence, severity, status, OWASP, CVSS, affected) **plus its
screenshot(s)**, with an "Add screenshot" control.

**How (reuse the existing screenshot slot — one source of truth):**

- `refreshFindings` (web.py ~1139) renders rows with a click handler; clicking opens
  a detail panel populated from the already-fetched `/api/findings` row (evidence is
  already parsed there — no new GET endpoint needed).
- Screenshots for a finding are the **same** `config.report.findings[<id>].screenshots`
  slot the report panel already writes via `/api/report-settings` and that
  `build_report_md` already renders. The detail panel fetches report-settings, shows
  the images, and its "Add screenshot" reuses `uploadPicked` + saves back to
  `/api/report-settings` — so a screenshot attached in the detail view appears in the
  report and vice-versa.
- Auto-capture of a target page (needs a headless browser the app lacks) is a
  documented FUTURE add, out of scope.

**Tests:** primarily manual/UI (stdlib server, no JS test harness). Backend-verifiable
pieces: `/api/findings` returns the narrative evidence fields for a director-authored
finding; a screenshot saved via `/api/report-settings` for a finding id is present in
both report-settings readback and the rendered report. A short DOM-render/live
snapshot check may be added the way the toolbox panel screenshot was captured.

## Item 3 — LLM-authored report (Bug 3)

**What:** At report time, an LLM writes the **executive summary + methodology
narrative from the REAL run transcript** and the report assembles the director's
per-finding analyses (authored in item 2). The deterministic template becomes the
**offline / no-LLM fallback**.

**How:**

- **New store method** `list_events(eid)` → **all** events for an engagement in
  chronological (`id ASC`) order, including `data` (the capped `recent_events` cannot
  reconstruct a transcript). Used to build a compact transcript from the
  `agent_step` / `agent_session` / `agent_finding` / `agent_flag` / `agent_blocked`
  events.
- `build_report_md(store, eid, project_dir, reason_fn=None)` gains an optional
  `reason_fn`. When present, **one** `reason_fn` call turns the transcript + findings
  into the Executive Summary and Methodology prose (a narrative of what was actually
  done on *this* target). Per-finding sections need **no** extra LLM call — the rich
  data was authored during the run (item 2).
- **Fallback contract:** `reason_fn` is `None`, returns `None`/empty, or (via item 6)
  looks like an error → the deterministic sections render exactly as today. The
  template is unchanged; only the summary/methodology gain an LLM path.
- **Wiring both call sites:** the `report_ptes` module passes `ctx.reason`; the web
  on-demand report endpoint builds a `ReasoningLadder` from the engagement/settings
  `reasoning` config (mirroring `engine.py`) and passes a `reason_fn` — so the LLM
  report is available both during a run and on download, and degrades to the template
  when no provider is configured.

**Tests:** `list_events` returns all events in order with `data`; `build_report_md`
with a fake `reason_fn` embeds the LLM summary/methodology; with `reason_fn=None` (or
one returning `None`/error-shaped text) it produces the deterministic template
(byte-compatible with today for a no-narrative engagement).

## Item 6 — Ladder fallback fix (Bug 1)

**Root cause (proven):** `reason()` advances only on a backend exception or
`_is_refusal(text)` (empty / `REFUSAL_MARKERS`). A provider that returns an error or
unrecognized refusal *as its text* with exit 0 / HTTP 200 is accepted as valid.

**Fix — prefer status signals, then broaden text detection without over-triggering:**

1. **Prefer exit-code / HTTP-status signals (make more failures raise → advance):**
   - `_backend_http_api`: when a 200 body parses to an object with a top-level
     `error`, raise (so it advances via the existing exception path) instead of
     returning the error text.
   - `_backend_cli`: already raises on non-zero exit; additionally treat exit 0 with
     empty stdout **and** non-empty stderr as a failure to advance.
2. **Broaden text-based detection** with a new `_looks_like_error(text)` used
   alongside `_is_refusal`, matching known provider *error/unavailable* phrasings
   (e.g. "rate limit(ed)", "model unavailable", "not available", "not on your plan",
   "quota", "overloaded", "service unavailable", "try again later",
   "flagged for possible cybersecurity risk", "trusted access for cyber",
   "insufficient_quota") and JSON error envelopes.
3. **Guard against over-triggering on valid answers** (critical — a wrongly-discarded
   good answer needlessly downgrades to a weaker model, and finding text legitimately
   contains words like "rate limit"): the broadened detection fires **only** when the
   response is *short* (e.g. ≤ ~240 chars after stripping) **or** is an error-only
   JSON envelope. A normal long action/answer/report is never treated as an error.
   (Exact threshold + marker list are a plan-stage detail.)

**Tests (both directions required):**
- Error-as-text with exit 0 (a fake `cli`/`http_api` backend returning
  "model unavailable, rate-limited") → the ladder **advances** to the next provider.
- 200 body `{"error": {...}}` → advances.
- **Guard:** a valid short answer (e.g. `"22/tcp open ssh"`) and a long finding whose
  text contains "rate limiting is missing" → **not** treated as an error; the first
  provider's answer is returned.

## Item 7 — Per-role model ladders (global / per-role / mixed)

**What:** Settings lets the operator configure model ladders in three ways, and
**nothing is pinned to a specific model** — every ladder is built only from the
operator's own configured providers:

1. **Global ladder for all roles** (today's behavior): define one ladder; every role
   uses it.
2. **A ladder per role:** each of the six roles gets its own ladder.
3. **Global + selective override:** define the global ladder plus a ladder for only
   the role(s) that should differ; every other role inherits the global ladder.

**The six roles** — a canonical registry (e.g. `ROLES` in `atpt/reasoning.py`) so the
UI enumerates them and config keys are validated:

| Role key | What it is | Call site | Phase |
|---|---|---|---|
| `director` | ReAct executor (the engine brain) | `agent_offensive/loop.py` | exploit |
| `skill` | Toolbox skill distiller (on success) | `agent_offensive/distill.py` | exploit |
| `scope` | Guard LLM judge (**deferred**; config slot ready now) | `agent_offensive/guard.py` | scope |
| `map` | Attack-surface / PTT enricher | `map_ptt/module.py` | map |
| `exploit` | Classic exploit proposer (hbgpt) | `exploit_hbgpt/module.py` | exploit |
| `report` | Report author/manager (new, item 3) | `report_ptes` / web report | report |

Several roles share a *phase* but are distinct *roles*: `phase` gates safety `policy`
(`local_only` etc.); `role` selects the ladder. They are orthogonal keys.

**Config shape** — an optional `roles` override map nested in the existing `reasoning`
block (which already lives in global `app_settings` and can be overridden per
engagement, `engine.py:61`). `providers` stay top-level and **shared** — define each
key/endpoint once:

```json
{
  "reasoning": {
    "providers": { "claude": {…}, "codex": {…}, "ollama": {…}, "my_gateway": {…} },

    "ladder":     [ {"provider":"claude"}, {"provider":"codex"}, {"provider":"ollama"} ],
    "preference": ["claude","codex","ollama"],
    "policy":     { "exploit":"any", "map":"any" },

    "roles": {
      "director": { "ladder": [ {"provider":"my_gateway","model":"…"}, {"provider":"ollama"} ] },
      "report":   { "ladder": [ {"provider":"claude"} ] }
    }
  }
}
```

**Resolution** — `ReasoningLadder.reason(prompt, phase, role=None)`:

1. If `role` is set and `reasoning.roles[role]` exists → use that block's
   `ladder`/`preference` (and its `policy` if present, else the global `policy`).
2. Otherwise → the global `ladder`/`preference`/`policy` (today's path).
3. `providers` is **always** the shared top-level dict.

`ctx.reason(prompt, phase, role=None)` grows a `role` argument and passes it through;
each call site names its role. `role=None` and a missing `roles` key both mean
"global ladder", so this is **fully backward-compatible**. The three modes are exactly
no `roles` (1) / every role in `roles` (2) / some roles in `roles` (3).

**Bug-1 interaction:** the fallback fix (item 6) lives in the ladder mechanism, so it
applies to *whichever* ladder is in effect — global or per-role.

**UI (Settings):** the existing ladder editor becomes the **Global** ladder. Below it,
a per-role section lists the six roles; each defaults to **"Use global ladder"** and
can switch to **"Custom"**, revealing the same ladder-editor widget scoped to that
role and drawing from the same provider list. Roles without a custom ladder show
"(uses global)". Because the UI only offers the operator's configured providers, a box
with only a local Ollama — or only a hosted key — works for every role; no model is
hardcoded.

**Tests:** a role with an override resolves to its own ladder; a role without one falls
back to the global ladder; `providers` are shared across both; no `roles` key →
identical to today (backward compat); an unknown/typo role key falls back to global and
never crashes.

---

## Data flow (end to end, after the change)

```
Director loop (item 1, default engine)
  ├─ command/session steps → assets, _scan_flags/harvest findings   (safety net)
  ├─ finding action (item 2) → rich finding {…, evidence:{description, reproduction,
  │                                          impact, remediation, confidence}}
  └─ every reason() call resolves its ROLE's ladder (item 7), then rides it with
        real fallback (item 6). No role is pinned to a specific model.
        ↓ persisted incrementally
atpt/state.py findings (item 4: narrative in evidence JSON, no migration)
        ↓                                   ↓
web.py findings table → clickable        report_ptes.build_report_md(reason_fn)
  detail panel (item 5) + screenshots       ├─ LLM summary+methodology from
  (config.report.findings[id].screenshots)  │  list_events transcript (item 3)
        ↕ same slot ↔ report                 ├─ per-finding: render authored fields
                                             └─ no reason_fn / error → template fallback
```

## Testing plan (summary)

All LLM-dependent tests use a **fake reasoner** (scripted text) — no real LLM, no
network. Full suite: `python3 -m pytest -q tests/` (baseline ~312 green).

- Ladder: error-as-text/exit-0 advances; 200-with-error advances; valid short answer
  and long "rate limit" finding text do **not** advance. (Item 6)
- `parse_action` finding kind; loop appends a well-formed rich finding and continues;
  malformed finding is non-fatal; flags/harvest still fire. (Item 2)
- Finding round-trips through the store with `evidence` narrative; `build_report_md`
  renders it and prefers `evidence.remediation`. (Items 4, 3)
- `list_events` returns all events in order with `data`. (Item 3)
- `build_report_md` with a fake `reason_fn` embeds narrative; with none → template.
  (Item 3)
- New-engagement default enables the director; toggle switches engines; existing
  config untouched. (Item 1)
- `/api/findings` exposes narrative fields; screenshot saved via `/api/report-settings`
  shows in report readback. (Item 5)
- Per-role ladder resolves to its override; a role without one falls back to global;
  `providers` shared; no `roles` key → today's behavior; unknown role key → global.
  (Item 7)

## Settled decisions (flagged for review)

- **D1 — narrative finding fields ride the existing `evidence` JSON, not new
  columns.** Zero migration, backward-compatible; the fields we add are never queried
  in SQL. (Item 4)
- **D2 — findings are authored during the run; the report adds exactly one narrative
  LLM pass.** Bounds cost/latency when the configured primary is slow/expensive
  (e.g. a CLI-driven model at ~75–140s a call); per-finding LLM calls at report time
  would be too slow. Model-agnostic — holds for any provider. (Items 2, 3)
- **D3 — "director as engine" = default the existing opt-in flag on for new
  engagements + a visible toggle**, reusing the existing mutual-exclusion wiring,
  rather than building a new engine dispatcher. Smallest blast radius, backward
  compatible. (Item 1)
- **D4 — screenshots stay operator-attached and reuse the one existing
  `config.report.findings[<id>].screenshots` slot** for both the UI detail and the
  report. Auto-capture is deferred (no headless browser). (Item 5)
- **D5 — the ladder's broadened error detection is gated on short/error-envelope
  responses** so it never discards a valid long answer. (Item 6)
- **D6 — per-role ladders are an override layer over a shared global ladder, with
  shared provider definitions.** Modes 1/2/3 fall out of "role override present or
  not"; no role is pinned to a specific model; a missing `roles` key = today's
  behavior. (Item 7)

## Open for the implementation-plan stage

- Exact `_looks_like_error` marker list + the short-response threshold, and whether
  step 1 (status-signal) fixes ship before/with step 2 (text detection).
- `_status_from_confidence` mapping (which confidence values promote to `validated`
  vs `candidate`, and how that interacts with `validate_xalgorix`).
- The report transcript-compaction shape (which event kinds, how much per event) fed
  to the single narrative `reason_fn` call.
- Web engine-toggle placement + the create-engagement default wiring.
- Whether the finding detail panel reads screenshots from `/api/report-settings` or a
  small merged endpoint (both are viable; report-settings reuse is the default).
- Canonical role names/labels for the registry, and whether `policy` (`local_only`)
  is overridable per role or stays global-only. (Item 7)

---

## Post-approval additions (2026-09-19) — recon split, scope agent, findings director, debugger agent

Captured after spec approval; the operator expanded the design to a small **team of
role-specialised agents**. Items 8–10 extend this spec's role model directly; item 11
is an independent subsystem, a strong candidate for its own spec+plan. Two decisions
are pending (the debugger's bug-report mechanism; execution sequencing). **Safety is
unchanged** — every command still passes the deterministic `ScopeGuard`, and the scope
flow below keeps a deterministic final gate.

### Item 8 — Recon is two phases, two experts (not one)

Recon splits into:
- **Passive recon — OSINT expert** (role `osint`): open-source intelligence only; no
  active probing of the target beyond what public sources require.
- **Active recon** (role `active_recon`): direct enumeration of in-scope hosts (the
  current nmap/httpx-style work).

Both run every engagement — **recon is 2 phases, not 1**. CTF is treated **like any
other job**: the OSINT phase always runs; for a THM/HTB box its OSINT input is the
**challenge-page** text/URL the operator supplies (there is no public footprint),
otherwise it is ordinary OSINT. Phase order in the director engine:
`osint → active_recon → map → exploit → validate → report`. Both roles join the
registry and get per-role ladders (item 7).

### Item 9 — Conversational scope agent (role `scope`, reframed)

The `scope` role (previously a deferred command-judge) becomes an **interactive scope
agent** that behaves like an ordinary LLM chat. Two setup paths:

1. **Scope typed in Settings:** at engagement start the agent **restates the
   normalised scope in plain language and asks the operator to approve it** (catching
   typos / a wrong octet / an unintended CIDR) — a chat, not a modal.
2. **No scope defined:** the agent **elicits the scope conversationally**, then — only
   after explicit operator approval — **writes the settings itself**.

**SAFETY INVARIANT (non-negotiable):** the LLM assists *defining and explaining*
scope; it is **never the sole gate**. The deterministic `ScopeGuard` wall stays, and a
**deterministic final confirmation of the normalised in-scope targets** (the existing
startup gate, hashed so a later edit re-confirms) still stands behind the chat. The
agent can never widen scope or approve on the operator's behalf.

### Item 10 — Findings director (confirmation, not new scope)

The director authors findings via the first-class `finding` action (item 2); the
automatic flag/asset harvest stays a **safety net only**. Recorded because the operator
named the "findings director" explicitly — it is the director doing findings, not a
separate walk.

### Item 11 — Debugger / support agent (role `debugger`) — likely its own spec+plan

A **separate support-chat agent**: when something in the app is not working for the
operator, it diagnoses the problem. If it is **operator error**, it guides them to the
fix in chat. If it is a **bug**, it files a report to the app repo for the maintainers.
It reads app logs/state to diagnose (**read-only** — it never changes settings or runs
engagement actions). **OPEN DECISION:** the bug-report mechanism for a **self-hosted
community** app (a prefilled GitHub-issue link the operator submits / the operator's own
`gh`/token when present / a hosted intake endpoint). Independent of the
findings/report/ladder spine, so a strong candidate for its **own spec + plan**.

### Role registry after these additions

`director, osint, active_recon, skill, scope, map, exploit, report, debugger` — each
independently ladder-configurable (item 7); nothing pinned to a specific model.
