# LLM Director + Rich Findings + LLM Report + Per-Role Ladders — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the LLM the director of an engagement — it authors each finding as its own reasoned conclusion, writes the report from the real run, is the default engine, is configurable per role, and actually falls back between models when one fails.

**Architecture:** Additive changes across the existing stdlib-only core. The reasoning ladder gains error-shaped fallback and a per-role override layer. The offensive agent's ReAct loop gains a `finding` action that persists rich, director-authored findings (narrative carried inside the existing `evidence` JSON — no schema migration). The PTES report gains an optional one-call LLM narrative pass over the real event transcript, with the deterministic template as the offline fallback. The web console defaults to the director engine, makes findings clickable with a detail+screenshot view, and exposes per-role ladders in Settings.

**Tech Stack:** Python 3 stdlib only (`atpt/`, `modules/`), SQLite store, stdlib `http.server` web console, `unittest`/`pytest` tests. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-19-llm-director-and-rich-findings-design.md` (items 1–7, decisions D1–D6). Read it alongside this plan.

## Global Constraints

- **Stdlib-only** for `atpt/` and `modules/` — no new third-party imports.
- **Safety is untouched:** the deterministic `ScopeGuard` wall, the one-time startup scope-confirmation gate, and semi-mode per-step approvals must behave exactly as before. No task weakens enforcement; no guardrail-bypass prompt engineering.
- **Model-agnostic:** never hardcode a provider or model as a role's brain. All provider/model/ladder choices come from operator config.
- **Backward-compatible:** absent config keys (`reasoning.roles`, `offensive_agent` on an old engagement, `reason_fn=None`) must reproduce today's behavior. Baseline ≈ **312 tests green**.
- **Full suite:** `python3 -m pytest -q tests/`. Focused: `python3 -m unittest tests.test_<name> -v` (NOTE: `unittest discover` is broken here — it collides with the `atpt` CLI; use pytest for the whole suite).
- **Commits:** conventional-commit messages (`feat:`/`fix:`/`docs:`). Subagents cannot commit here (a classifier blocks them) — the controller stages-check and commits each task's work. End commit messages with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Ladder fallback on error-shaped responses (Item 6 / Bug 1)

**Files:**
- Modify: `atpt/reasoning.py` (add `_looks_like_error`; call it in `reason()`; make `_backend_http_api` raise on a 200 error-envelope; make `_backend_cli` raise on exit-0-with-empty-stdout-and-stderr)
- Test: `tests/test_reasoning_ladder.py` (extend)

**Interfaces:**
- Consumes: existing `ReasoningLadder(config).reason(prompt, phase)`, module-level `BACKENDS` dict, `_is_refusal`.
- Produces: `_looks_like_error(text: str) -> bool`; `reason()` now advances to the next provider when a returned response is error/refusal-shaped, without over-triggering on valid short answers.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_reasoning_ladder.py` inside `ReasoningLadderTest`:

```python
    def test_error_as_text_with_exit0_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            return "Model unavailable — you are rate-limited. Try again later." \
                if len(calls) == 1 else "RECOVERED"
        self._install(fake)
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "RECOVERED")
        self.assertEqual(res.provider, "p2")

    def test_json_error_envelope_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            return '{"error":{"message":"insufficient_quota"}}' \
                if len(calls) == 1 else "RECOVERED"
        self._install(fake)
        self.assertEqual(ReasoningLadder(CFG).reason("hi", "map").text, "RECOVERED")

    def test_valid_short_answer_is_not_an_error(self):
        self._install(lambda cfg, p: "22/tcp open ssh")
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "22/tcp open ssh")
        self.assertEqual(res.provider, "p1")

    def test_long_answer_containing_marker_is_not_an_error(self):
        # A real finding legitimately mentions "rate limit" — a long response must
        # never be discarded as error-shaped.
        long = "Finding: the login endpoint has no rate limiting, so credential " \
               "stuffing is possible. " + ("Details. " * 40)
        self._install(lambda cfg, p: long)
        self.assertEqual(ReasoningLadder(CFG).reason("hi", "map").text, long)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_reasoning_ladder -v`
Expected: the two `*_advances` tests FAIL (the error text is returned as a valid answer, so `provider` is `p1`, not `p2`); the two guard tests PASS already.

- [ ] **Step 3: Add `_looks_like_error` and wire it into `reason()`**

In `atpt/reasoning.py`, after the `_is_refusal` function add:

```python
ERROR_MARKERS = (
    "rate limit", "rate-limited", "rate limited", "model unavailable",
    "not available", "not on your plan", "quota", "insufficient_quota",
    "overloaded", "service unavailable", "try again later",
    "flagged for possible cybersecurity risk", "trusted access for cyber",
    "you do not have access", "no access to",
)
_ERR_MAX = 240  # only SHORT responses are judged error-shaped by phrase


def _looks_like_error(text: str) -> bool:
    """True when a process-level success (exit 0 / HTTP 200) actually carried an
    error or unrecognized refusal AS its text. Guarded so a valid long answer — or
    a finding that merely mentions 'rate limit' — is never discarded."""
    t = (text or "").strip()
    if not t:
        return False  # empty is handled by _is_refusal
    try:
        obj = json.loads(t)
        if isinstance(obj, dict) and obj.get("error"):
            return True
    except Exception:
        pass
    if len(t) <= _ERR_MAX and any(m in t.lower() for m in ERROR_MARKERS):
        return True
    return False
```

In `ReasoningLadder.reason()`, right after the existing `if _is_refusal(text):` block, add:

```python
            if _looks_like_error(text):
                self._emit("reasoning_error",
                           f"provider '{provider}' returned an error-shaped response; advancing",
                           "warn")
                continue
```

- [ ] **Step 4: Prefer status signals in the backends**

In `_backend_cli`, after the non-zero-exit check, add:

```python
    if not proc.stdout.strip() and proc.stderr.strip():
        raise RuntimeError(f"cli exit 0 but empty stdout; stderr: {proc.stderr[-200:]}")
```

In `_backend_http_api`, replace the final `with urllib.request.urlopen(...)` return with:

```python
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 120)) as resp:
        data = json.loads(resp.read().decode())
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(f"api error: {str(data['error'])[:200]}")
    return _extract_text(data)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_reasoning_ladder -v`
Expected: all tests PASS (including the pre-existing `test_first_ok_wins`, `test_refusal_advances`, `test_error_advances`, `test_exhausted_returns_none`).

- [ ] **Step 6: Run the reasoning-backends test too (guard against regressions)**

Run: `python3 -m unittest tests.test_reasoning_backends -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add atpt/reasoning.py tests/test_reasoning_ladder.py
git commit -m "fix(reasoning): fall back on error-shaped responses (exit0/200), not just exceptions"
```

---

### Task 2: Per-role ladders + role threading (Item 7 backend)

**Files:**
- Modify: `atpt/reasoning.py` (`ROLES` registry; `reason(prompt, phase, role=None)`; per-role resolution; `_allowed` takes a policy)
- Modify: `atpt/module.py` (`RunContext.reason(prompt, phase, role=None)`)
- Modify: `modules/agent_offensive/module.py` (director/skill roles)
- Modify: `modules/map_ptt/module.py` (map role)
- Modify: `modules/exploit_hbgpt/module.py` (exploit role)
- Test: `tests/test_reasoning_ladder.py`, `tests/test_ctx_reason.py`

**Interfaces:**
- Consumes: Task 1's `reason()`; the config shape `{providers, ladder, preference, policy}`.
- Produces: `atpt.reasoning.ROLES = ("director","osint","active_recon","skill","scope","map","exploit","report")`; `ReasoningLadder.reason(prompt, phase, role=None)`; `RunContext.reason(prompt, phase, role=None)`. `role=None` and a missing `reasoning.roles` key both resolve to the global ladder (backward-compatible). `providers` are always shared top-level.

- [ ] **Step 1: Write the failing tests (ladder)**

Append to `tests/test_reasoning_ladder.py`:

```python
ROLE_CFG = {
    "providers": {"p1": {"backend": "fake"}, "p2": {"backend": "fake"}},
    "ladder": [{"provider": "p1"}],
    "roles": {"report": {"ladder": [{"provider": "p2"}]}},
}


class RoleLadderTest(unittest.TestCase):
    def setUp(self):
        self._saved = dict(reasoning.BACKENDS)
        reasoning.BACKENDS.clear()
        reasoning.BACKENDS["fake"] = lambda cfg, p: f"OK:{cfg.get('_who','?')}"

    def tearDown(self):
        reasoning.BACKENDS.clear(); reasoning.BACKENDS.update(self._saved)

    def test_role_override_uses_own_ladder(self):
        # tag each provider so we can see which one answered
        reasoning.BACKENDS["fake"] = lambda cfg, p: "ANS"
        L = ReasoningLadder(ROLE_CFG)
        self.assertEqual(L.reason("hi", "report", role="report").provider, "p2")

    def test_role_without_override_uses_global(self):
        self.assertEqual(ReasoningLadder(ROLE_CFG).reason("hi", "map", role="map").provider, "p1")

    def test_unknown_role_falls_back_to_global(self):
        self.assertEqual(ReasoningLadder(ROLE_CFG).reason("hi", "map", role="bogus").provider, "p1")

    def test_no_roles_key_is_global(self):
        cfg = {"providers": {"p1": {"backend": "fake"}}, "ladder": [{"provider": "p1"}]}
        self.assertEqual(ReasoningLadder(cfg).reason("hi", "map").provider, "p1")
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_reasoning_ladder.RoleLadderTest -v`
Expected: FAIL — `reason()` currently takes no `role` argument (TypeError).

- [ ] **Step 3: Implement per-role resolution**

In `atpt/reasoning.py` add near the top (after `REFUSAL_MARKERS`):

```python
ROLES = ("director", "osint", "active_recon", "skill", "scope", "map", "exploit", "report")
```

In `ReasoningLadder.__init__`, after `self.policy = cfg.get("policy", {})` add:

```python
        self.roles: dict = cfg.get("roles", {}) or {}
```

Change `_allowed` to accept the effective policy:

```python
    def _allowed(self, provider_cfg: dict, phase: str, policy: dict) -> bool:
        pol = (policy or {}).get(phase, "any")
        if pol == "local_only":
            return provider_cfg.get("backend") == "ollama"
        return True
```

Replace `_entries` and `reason` with role-aware versions:

```python
    def _resolve(self, role):
        rc = self.roles.get(role) if role else None
        if isinstance(rc, dict):
            return (rc.get("ladder") or [], rc.get("preference") or [],
                    rc.get("policy") or self.policy)
        return self.ladder, self.preference, self.policy

    def _entries(self, ladder, preference):
        if ladder:
            for e in ladder:
                yield e.get("provider"), e.get("model"), e.get("effort")
        else:
            for name in preference:
                yield name, None, None

    def reason(self, prompt: str, phase: str, role: str | None = None) -> "ReasoningResult | None":
        ladder, preference, policy = self._resolve(role)
        for provider, model, effort in self._entries(ladder, preference):
            pc = self.providers.get(provider)
            if not pc or not self._allowed(pc, phase, policy):
                continue
            backend = BACKENDS.get(pc.get("backend"))
            if backend is None:
                continue
            cfg = dict(pc)
            if model:
                cfg["model"] = model
            if effort:
                cfg["effort"] = effort
            try:
                text = backend(cfg, prompt)
            except Exception as exc:
                self._emit("reasoning_error", f"provider '{provider}' error: {exc}", "warn")
                continue
            if _is_refusal(text):
                self._emit("reasoning_refused", f"provider '{provider}' refused; advancing", "info")
                continue
            if _looks_like_error(text):
                self._emit("reasoning_error",
                           f"provider '{provider}' returned an error-shaped response; advancing", "warn")
                continue
            return ReasoningResult(text=text, provider=provider)
        return None
```

- [ ] **Step 4: Thread `role` through `ctx.reason` and update its fake**

In `atpt/module.py` change `RunContext.reason`:

```python
    def reason(self, prompt: str, phase: str, role: str | None = None) -> "str | None":
        if self.reasoner is None:
            return None
        if self.goals:
            prompt = f"Engagement goals: {self.goals}\n\n{prompt}"
        res = self.reasoner.reason(prompt, phase, role)
        return res.text if res else None
```

In `tests/test_ctx_reason.py` update the fake and add a passthrough test:

```python
class _FakeLadder:
    def __init__(self, result):
        self._result = result
        self.seen = None

    def reason(self, prompt, phase, role=None):
        self.seen = (phase, role)
        return self._result
```

```python
    def test_reason_forwards_role(self):
        lad = _FakeLadder(ReasoningResult(text="ANS", provider="p1"))
        ctx = self._ctx(lad)
        self.assertEqual(ctx.reason("hi", "report", role="report"), "ANS")
        self.assertEqual(lad.seen, ("report", "report"))
```

- [ ] **Step 5: Name the role at each existing call site**

In `modules/agent_offensive/module.py`, change the two `ctx.reason(p, "exploit")` lambdas:
- the `distill_fn`'s reason_fn → `reason_fn=lambda p: ctx.reason(p, "exploit", role="skill")`
- the `run_loop(... reason_fn=lambda p: ctx.reason(p, "exploit", role="director") ...)`

In `modules/map_ptt/module.py:63`, change `ctx.reason(prompt, phase="map")` → `ctx.reason(prompt, phase="map", role="map")`.

In `modules/exploit_hbgpt/module.py:90`, change `ctx.reason(PROMPT + f"{title} (host={host})", phase="exploit")` → `ctx.reason(PROMPT + f"{title} (host={host})", phase="exploit", role="exploit")`.

- [ ] **Step 6: Run the tests**

Run: `python3 -m unittest tests.test_reasoning_ladder tests.test_ctx_reason -v`
Expected: PASS.

- [ ] **Step 7: Run the modules that were re-wired**

Run: `python3 -m unittest tests.test_map_ptt tests.test_exploit_hbgpt tests.test_agent_module -v`
Expected: PASS (role is an added keyword; behavior unchanged when no `roles` config).

- [ ] **Step 8: Commit**

```bash
git add atpt/reasoning.py atpt/module.py modules/agent_offensive/module.py modules/map_ptt/module.py modules/exploit_hbgpt/module.py tests/test_reasoning_ladder.py tests/test_ctx_reason.py
git commit -m "feat(reasoning): per-role model ladders with global fallback; thread role through call sites"
```

---

### Task 3: Store — list_events + rich-finding evidence round-trip (Items 3-prereq, 4)

**Files:**
- Modify: `atpt/state.py` (add `list_events`)
- Test: `tests/test_state_findings.py` (evidence round-trip), `tests/test_state_events.py` (new; `list_events`)

**Interfaces:**
- Consumes: existing `SQLiteStore.add_event`, `upsert_finding`, `list_findings`.
- Produces: `SQLiteStore.list_events(eid) -> list[dict]` returning ALL events in chronological (`id ASC`) order with columns `ts, phase, module, level, kind, message, data`. Confirms the Item-4 contract: a finding's narrative (`description`, `reproduction`, `impact`, `remediation`, `confidence`) round-trips inside the `evidence` JSON with no schema change.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_state_events.py`:

```python
import tempfile, unittest
from pathlib import Path
from atpt.state import SQLiteStore


class ListEventsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_events_all_in_order_with_data(self):
        for i in range(20):
            self.store.add_event("e1", "exploit", "agent", "info",
                                 "agent_step", f"step {i}", {"n": i})
        evs = self.store.list_events("e1")
        self.assertEqual(len(evs), 20)                     # not capped at 15
        self.assertEqual(evs[0]["message"], "step 0")      # ascending
        self.assertEqual(evs[-1]["message"], "step 19")
        self.assertIn("data", evs[0])                      # includes data column
```

Append to `tests/test_state_findings.py` (inside its test class):

```python
    def test_rich_finding_evidence_round_trips(self):
        import json
        self.store.upsert_finding("e1", {
            "title": "Blind SQLi in /login", "severity": "high", "status": "validated",
            "domain": "Web", "cvss": 8.1, "owasp": "A03", "source_tool": "agent-director",
            "evidence": {"asset_value": "http://t/login", "description": "boolean-blind SQLi",
                         "reproduction": "curl ...' OR 1=1-- => 200 vs 500", "impact": "auth bypass",
                         "remediation": "use parameterized queries", "confidence": "confirmed"}})
        row = self.store.list_findings("e1")[0]
        ev = json.loads(row["evidence"])
        self.assertEqual(ev["reproduction"], "curl ...' OR 1=1-- => 200 vs 500")
        self.assertEqual(ev["remediation"], "use parameterized queries")
        self.assertEqual(row["source_tool"], "agent-director")
```

(`tests/test_state_findings.py` already builds `self.store` with an engagement `e1` in `setUp`; reuse it. If its engagement id differs, use that id.)

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_state_events -v`
Expected: FAIL — `SQLiteStore` has no attribute `list_events`.

- [ ] **Step 3: Implement `list_events`**

In `atpt/state.py`, in the events section (right after `recent_events`), add:

```python
    def list_events(self, eid) -> list[dict]:
        """ALL events for an engagement, chronological, including `data` — used to
        reconstruct the run transcript for the LLM-authored report."""
        return [dict(r) for r in self.cx.execute(
            "SELECT ts,phase,module,level,kind,message,data FROM events "
            "WHERE engagement_id=? ORDER BY id", (eid,))]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_state_events tests.test_state_findings -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add atpt/state.py tests/test_state_events.py tests/test_state_findings.py
git commit -m "feat(state): list_events(all, chronological, with data); document rich-finding evidence contract"
```

---

### Task 4: `finding` action — director authors rich findings (Item 2)

**Files:**
- Modify: `modules/agent_offensive/actions.py` (add `finding` kind + `Action.finding`)
- Modify: `modules/agent_offensive/loop.py` (finding branch, `_status_from_confidence`, prompt line)
- Test: `tests/test_agent_actions.py`, `tests/test_agent_loop.py`

**Interfaces:**
- Consumes: existing `parse_action(text) -> Action|None`; `run_loop(*, goal, guard, reason_fn, max_steps, emit, execute_fn, harvest_fn, ...)`.
- Produces: `Action(kind="finding", finding=<dict>)`; the loop appends a store-ready finding dict `{title, severity, domain, cvss, owasp, status, source_tool:"agent-director", evidence:{asset_value, description, reproduction, impact, remediation, confidence}}` and continues (does not end the loop). `_scan_flags`/`harvest` safety net unchanged.

- [ ] **Step 1: Write the failing tests (parser)**

Append to `tests/test_agent_actions.py`:

```python
    def test_parse_finding_action(self):
        from modules.agent_offensive.actions import parse_action
        a = parse_action('{"finding": {"title":"SQLi","severity":"high",'
                         '"how_i_proved_it":"curl X"}, "rationale":"proven"}')
        self.assertEqual(a.kind, "finding")
        self.assertEqual(a.finding["title"], "SQLi")
        self.assertEqual(a.finding["how_i_proved_it"], "curl X")

    def test_finding_must_be_object(self):
        from modules.agent_offensive.actions import parse_action
        self.assertIsNone(parse_action('{"finding": "not-an-object"}'))
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_agent_actions -v`
Expected: FAIL — no `finding` kind (returns a `command`/`None`).

- [ ] **Step 3: Implement the parser branch**

In `modules/agent_offensive/actions.py`, add to the `Action` dataclass:

```python
    finding: dict = field(default_factory=dict)
```

In `parse_action`, add this block **before** the `cmd = obj.get("command")` line:

```python
    if obj.get("finding") is not None:
        spec = obj.get("finding")
        if isinstance(spec, dict):
            return Action(kind="finding", finding=spec, rationale=rationale)
        return None
```

- [ ] **Step 4: Run the parser tests**

Run: `python3 -m unittest tests.test_agent_actions -v`
Expected: PASS.

- [ ] **Step 5: Write the failing tests (loop)**

Append to `tests/test_agent_loop.py` inside `LoopTest`:

```python
    def test_finding_action_records_rich_finding(self):
        scripted = iter([
            '{"finding":{"title":"SQLi in login","severity":"high",'
            '"what_it_is":"boolean-blind SQLi","how_i_proved_it":"curl \\" OR 1=1",'
            '"affected":"http://t/login","impact":"auth bypass",'
            '"remediation":"parameterize","confidence":"confirmed"}}',
            '{"done": true}',
        ])
        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: next(scripted), max_steps=5,
            emit=lambda *a, **k: None, execute_fn=lambda a, timeout=300: {"rc": 0, "out": "", "err": ""},
            harvest_fn=lambda a, r: ([], []))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["title"], "SQLi in login")
        self.assertEqual(f["status"], "validated")           # confidence "confirmed"
        self.assertEqual(f["source_tool"], "agent-director")
        self.assertEqual(f["evidence"]["reproduction"], 'curl " OR 1=1')
        self.assertEqual(f["evidence"]["impact"], "auth bypass")

    def test_malformed_finding_is_nonfatal(self):
        scripted = iter(['{"finding":{"title":"no severity"}}', '{"done":true}'])
        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: next(scripted), max_steps=5,
            emit=lambda *a, **k: None, execute_fn=lambda a, timeout=300: {"rc": 0, "out": "", "err": ""},
            harvest_fn=lambda a, r: ([], []))
        self.assertEqual(len(findings), 0)                    # rejected, not crashed
        self.assertIn("done", summary.lower())
```

- [ ] **Step 6: Run to verify failure**

Run: `python3 -m unittest tests.test_agent_loop -v`
Expected: FAIL — the finding action falls through to the command path (no finding recorded).

- [ ] **Step 7: Implement the loop branch + helper + prompt line**

In `modules/agent_offensive/loop.py`, add a helper near `_scan_flags`:

```python
def _status_from_confidence(conf):
    c = str(conf or "").strip().lower()
    return "validated" if c in ("confirmed", "high") else "candidate"
```

In `run_loop`, add this branch **after** the `if action.kind == "ssh":` block and **before** the `# kind == command` section:

```python
        if action.kind == "finding":
            fd = action.finding or {}
            title = str(fd.get("title") or "").strip()
            sev = str(fd.get("severity") or "").strip().lower()
            if not title or not sev:
                transcript.append("OBSERVATION: a finding needs at least a title and a "
                                  "severity; restate it as ONE finding JSON.")
                continue
            findings.append({
                "title": title, "severity": sev,
                "domain": fd.get("domain") or "General",
                "cvss": fd.get("cvss"), "owasp": fd.get("owasp"),
                "status": _status_from_confidence(fd.get("confidence")),
                "source_tool": "agent-director",
                "evidence": {
                    "asset_value": fd.get("affected"),
                    "description": fd.get("what_it_is") or fd.get("description"),
                    "reproduction": fd.get("how_i_proved_it"),
                    "impact": fd.get("impact"),
                    "remediation": fd.get("remediation"),
                    "confidence": fd.get("confidence"),
                },
            })
            emit("agent_finding", f"[agent] finding: {title} ({sev})",
                 data={"title": title, "severity": sev})
            transcript.append(f"OBSERVATION: recorded finding '{title}' ({sev}). "
                              f"Continue toward the goal.")
            continue
```

In the `_PROMPT` string, add this action line immediately before the `done` line:

```python
    '  {{"finding": {{"title":"...","severity":"critical|high|medium|low|info",'
    '"what_it_is":"...","how_i_proved_it":"the commands + output that prove it",'
    '"affected":"host/url/param","impact":"...","remediation":"...",'
    '"confidence":"confirmed|likely|tentative"}}}}  record a real issue YOU concluded\n'
```

- [ ] **Step 8: Run the loop tests**

Run: `python3 -m unittest tests.test_agent_loop tests.test_agent_actions -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add modules/agent_offensive/actions.py modules/agent_offensive/loop.py tests/test_agent_actions.py tests/test_agent_loop.py
git commit -m "feat(agent): first-class finding action — director authors rich, stored findings"
```

---

### Task 5: Director is the default engine + engine toggle (Item 1)

**Files:**
- Modify: `atpt/web.py` (`_create_engagement`: read `engine`, default the director on; create-form engine toggle in the HTML/JS)
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: existing `_create_engagement`, `WebApp(".", db_path=...).handle(...)`, `offensive_agent_on`.
- Produces: a UI-created engagement defaults to `config.offensive_agent.enabled = True`; passing `"engine":"classic"` in the create POST sets it `False`. Existing engagements' stored config is not rewritten.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web.py` inside `WebTest`:

```python
    def test_create_defaults_to_director_engine(self):
        self._post("/api/engagement", {"engagement": "d1", "mode": "semi",
            "scope": {"domains": {"web": {"enabled": True, "in": ["acme.com"]}}}})
        cfg = json.loads(SQLiteStore(self.db).get_engagement("d1")["config"] or "{}")
        self.assertTrue(cfg.get("offensive_agent", {}).get("enabled"))

    def test_create_classic_engine_disables_agent(self):
        self._post("/api/engagement", {"engagement": "c1", "mode": "semi", "engine": "classic",
            "scope": {"domains": {"web": {"enabled": True, "in": ["acme.com"]}}}})
        cfg = json.loads(SQLiteStore(self.db).get_engagement("c1")["config"] or "{}")
        self.assertFalse(cfg.get("offensive_agent", {}).get("enabled"))
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_web.WebTest.test_create_defaults_to_director_engine tests.test_web.WebTest.test_create_classic_engine_disables_agent -v`
Expected: FAIL — config is created empty (`{}`), so `enabled` is missing/false in the first test.

- [ ] **Step 3: Default the director on in `_create_engagement`**

In `atpt/web.py` `_create_engagement`, replace the `store.create_engagement(...)` call with:

```python
        engine = (data.get("engine") or "director")
        config = {"offensive_agent": {"enabled": engine != "classic"}}
        store.create_engagement(eid, data.get("name") or eid, scope, f"{eid}.scope.json",
                                data.get("mode") or "semi", config)
```

- [ ] **Step 4: Add the visible engine toggle to the create form (UI)**

Find the create-engagement form controls in the HTML (near `#createbtn`, ~line 1201) and add an engine selector, defaulting to Director, e.g.:

```html
<label class="hint">Engine
  <select id="engine">
    <option value="director" selected>Director (LLM drives the engagement)</option>
    <option value="classic">Classic pipeline (fixed scan chain)</option>
  </select>
</label>
```

In the `#createbtn` click handler, include the engine in the POST body:

```javascript
engine: ($('#engine') && $('#engine').value) || 'director',
```

(UI wiring is verified manually; the endpoint default/override is covered by Step 1's tests.)

- [ ] **Step 5: Run the tests**

Run: `python3 -m unittest tests.test_web -v`
Expected: PASS (all existing web tests plus the two new ones).

- [ ] **Step 6: Commit**

```bash
git add atpt/web.py tests/test_web.py
git commit -m "feat(web): director is the default engine for new engagements + visible engine toggle"
```

---

### Task 6: LLM-authored report narrative (Item 3 / Bug 3)

**Files:**
- Modify: `modules/report_ptes/module.py` (`build_report_md(store, eid, project_dir, reason_fn=None)`; narrative pass; fallback; `ReportPTES.run` passes `ctx.reason` role="report")
- Modify: `atpt/web.py` (`/api/report` builds a role="report" reason_fn from the engagement/settings reasoning config)
- Test: `tests/test_report.py` (or `tests/test_report_custom.py`)

**Interfaces:**
- Consumes: Task 3's `store.list_events(eid)`; Task 2's role-aware `ctx.reason(..., role="report")`; existing `build_report_md(store, eid, project_dir)` and its deterministic Executive-Summary/Methodology sections.
- Produces: `build_report_md(store, eid, project_dir, reason_fn=None)`. When `reason_fn` returns valid Markdown containing `## Executive Summary`, those two sections come from the LLM; otherwise (None/empty/error) the deterministic sections render exactly as today. `test_report_author.py`'s 3-arg calls keep working (default `reason_fn=None`). Also renders the director's per-finding narrative (What it is / How it was proven / Impact) and prefers `evidence.remediation` over the OWASP default, and coerces `cvss` to float-or-None so a non-numeric director cvss never crashes the sort/render.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_report.py` (it builds `self.store` + engagement; adapt ids to that file's setUp):

```python
    def test_llm_narrative_used_when_reason_fn_returns_valid_markdown(self):
        fake = lambda p: "## Executive Summary\nA custom LLM summary line.\n\n## Methodology\nWe enumerated then exploited."
        md = self.build(self.store, self.eid, self.pd, reason_fn=fake)
        self.assertIn("A custom LLM summary line.", md)
        self.assertIn("We enumerated then exploited.", md)

    def test_template_fallback_when_no_reason_fn(self):
        md = self.build(self.store, self.eid, self.pd)                 # reason_fn=None
        self.assertIn("## Executive Summary", md)
        self.assertIn("Phases executed", md)                          # deterministic methodology

    def test_template_fallback_when_reason_fn_returns_none(self):
        md = self.build(self.store, self.eid, self.pd, reason_fn=lambda p: None)
        self.assertIn("Phases executed", md)

    def test_renders_director_narrative_and_prefers_its_remediation(self):
        self.store.upsert_finding(self.eid, {
            "title": "SQLi in /login", "severity": "high", "status": "validated",
            "source_tool": "agent-director", "cvss": "high",   # non-numeric on purpose
            "evidence": {"asset_value": "http://t/login", "description": "boolean-blind SQLi",
                         "reproduction": "curl ...' OR 1=1-- -> 200 vs 500", "impact": "auth bypass",
                         "remediation": "use parameterized queries", "confidence": "confirmed"}})
        md = self.build(self.store, self.eid, self.pd)   # must NOT crash on non-numeric cvss
        self.assertIn("boolean-blind SQLi", md)          # description rendered
        self.assertIn("curl ...' OR 1=1", md)            # reproduction rendered
        self.assertIn("auth bypass", md)                 # impact rendered
        self.assertIn("use parameterized queries", md)   # director remediation, not OWASP default
```

(If `tests/test_report.py` does not already expose `self.build`, `self.eid`, `self.pd`, add them in its `setUp` mirroring `tests/test_report_author.py`: `self.build = <importlib-loaded build_report_md>`, `self.eid = "<its engagement id>"`, `self.pd = <project dir Path>`.)

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_report -v`
Expected: FAIL — `build_report_md()` takes 3 positional args, not `reason_fn`.

- [ ] **Step 3: Add the narrative pass to `build_report_md`**

In `modules/report_ptes/module.py`, add near the top-level helpers:

```python
_NARRATIVE_PROMPT = (
    "You are writing a penetration-test report from a REAL engagement. Using the "
    "findings and the run transcript below, output EXACTLY two Markdown sections and "
    "nothing else:\n"
    "## Executive Summary\n(3-6 sentences: what was tested, what was found, the business risk)\n"
    "## Methodology\n(a short narrative of what was actually done on THIS engagement)\n\n"
    "Findings:\n{findings}\n\nRun transcript:\n{transcript}\n")

_TRANSCRIPT_KINDS = {"agent_step", "agent_session", "agent_finding", "agent_flag", "agent_blocked"}


def _run_transcript(store, eid: str) -> str:
    if not hasattr(store, "list_events"):
        return ""
    lines = [f"- {e.get('kind')}: {e.get('message')}"
             for e in store.list_events(eid) if e.get("kind") in _TRANSCRIPT_KINDS]
    return "\n".join(lines[-80:])
```

Change the signature and the two-section emission. Replace `def build_report_md(store, eid: str, project_dir: Path) -> str:` with:

```python
def build_report_md(store, eid: str, project_dir: Path, reason_fn=None) -> str:
```

Then locate the block that currently appends `"## Executive Summary"` … through the end of the `"## Methodology"` paragraph, and wrap it:

```python
    narrative = None
    if reason_fn is not None:
        fsum = "\n".join(f"- {f.get('title')} [{(f.get('severity') or 'info')}]"
                         for f in reported) or "- (none)"
        try:
            narrative = reason_fn(_NARRATIVE_PROMPT.format(
                findings=fsum, transcript=_run_transcript(store, eid)))
        except Exception:
            narrative = None
    if narrative and "## Executive Summary" in narrative:
        L.append(narrative.strip())
        L.append("")
    else:
        # --- existing deterministic Executive Summary + Methodology blocks ---
        L.append("## Executive Summary")
        L.append("")
        # ... (keep the current summary + methodology lines verbatim here) ...
        L.append("")
```

(Keep the existing summary/methodology lines exactly as they are, moved inside the `else`.)

- [ ] **Step 4: Have the module and web pass a role="report" reason_fn**

In `modules/report_ptes/module.py` `ReportPTES.run`, change the `md = build_report_md(...)` line:

```python
        rf = None if ctx.dry_run else (lambda p: ctx.reason(p, "report", role="report"))
        md = build_report_md(ctx.store, eid, ctx.project_dir, reason_fn=rf)
```

In `atpt/web.py`, add a helper method on `WebApp`:

```python
    def _report_reason_fn(self, eid):
        store = self._store()
        eng = store.get_engagement(eid) or {}
        cfg = json.loads(eng.get("config") or "{}")
        rc = cfg.get("reasoning") or (store.get_settings() or {}).get("reasoning")
        if not rc:
            return None
        from .reasoning import ReasoningLadder
        ladder = ReasoningLadder(rc)
        def rf(prompt):
            res = ladder.reason(prompt, "report", role="report")
            return res.text if res else None
        return rf
```

and change the `/api/report` handler (line ~454):

```python
        if path == "/api/report" and method == "GET":
            md = self._report_builder()(store, eid, self.project_dir,
                                        reason_fn=self._report_reason_fn(eid))
```

- [ ] **Step 5: Render the director's narrative fields + coerce cvss safely**

Director-authored findings (Task 4) carry their narrative inside `evidence` and MAY set a non-numeric `cvss` (e.g. `"high"`). Two changes to `build_report_md`'s per-finding path in `modules/report_ptes/module.py`:

(a) **Coerce cvss** so the sort key and CVSS line never crash on a non-numeric value. Add a top-level helper:

```python
def _cvss_num(f):
    try:
        return float(f.get("cvss"))
    except (TypeError, ValueError):
        return None
```

Use it in the sort key (replace `-(f.get("cvss") or 0)` with `-(_cvss_num(f) or 0)`) and set `cvss = _cvss_num(f)` where the per-finding CVSS line is built.

(b) **Render the narrative + prefer the director's remediation.** In the per-finding loop, after the existing `- **Affected:**` / `- **Evidence:**` lines, add:

```python
        if ev.get("description"):
            L.append(f"- **What it is:** {ev['description']}")
        if ev.get("reproduction"):
            L.append(f"- **How it was proven:** {ev['reproduction']}")
        if ev.get("impact"):
            L.append(f"- **Impact:** {ev['impact']}")
```

and change the remediation line to prefer the director's own remediation over the OWASP-keyed default:

```python
        rem = ev.get("remediation") or _REMEDIATION.get(str(owasp).split()[0] if owasp else "", _DEFAULT_REMEDIATION)
        L.append(f"- **Remediation:** {rem}")
```

- [ ] **Step 6: Run the report tests (including the pre-existing author tests)**

Run: `python3 -m unittest tests.test_report tests.test_report_author tests.test_report_custom -v`
Expected: PASS — the LLM path is used only with a valid `reason_fn`; `test_report_author.py`'s 3-arg calls fall to the template.

- [ ] **Step 7: Commit**

```bash
git add modules/report_ptes/module.py atpt/web.py tests/test_report.py
git commit -m "feat(report): LLM-authored narrative + rendered per-finding director analysis; cvss-safe; template fallback"
```

---

### Task 7: Clickable finding detail + screenshots (Item 5 / Bug 2)

**Files:**
- Modify: `atpt/web.py` (make findings rows clickable; a detail panel rendering the narrative + screenshots; "Add screenshot" reusing `uploadPicked` → `/api/report-settings`)
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: Task 4's rich findings; existing `/api/findings` (returns rows with parsed `evidence`), `/api/report-settings` (GET/POST `config.report.findings[<id>].screenshots`), `uploadPicked`.
- Produces: the findings table renders clickable rows opening a detail view of `evidence.description / reproduction / impact / remediation / confidence` + severity/status/owasp/cvss + affected, plus screenshots from `config.report.findings[<id>].screenshots`; "Add screenshot" saves back to that same slot (single source of truth shared with the report).

- [ ] **Step 1: Write the failing (backend-verifiable) tests**

Append to `tests/test_web.py` inside `WebTest`:

```python
    def test_findings_expose_narrative_evidence(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                "e1.scope.json", "semi", {})
        store.upsert_finding("e1", {"title": "SQLi", "severity": "high",
            "source_tool": "agent-director",
            "evidence": {"description": "blind SQLi", "reproduction": "curl X",
                         "impact": "bypass", "remediation": "paramize"}})
        st, _, body, _ = self._get("/api/findings", eng="e1")
        row = json.loads(body)["findings"][0]
        self.assertEqual(row["evidence"]["reproduction"], "curl X")
        self.assertEqual(row["evidence"]["remediation"], "paramize")

    def test_finding_screenshot_slot_round_trips(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                "e1.scope.json", "semi", {})
        store.upsert_finding("e1", {"title": "X", "severity": "low", "evidence": {}})
        fid = store.list_findings("e1")[0]["id"]
        body = json.dumps({"findings": {str(fid): {"include": True, "screenshots": ["/tmp/a.png"]}}}).encode()
        st, _, _, _ = self.app.handle("POST", "/api/report-settings", {"eng": "e1"}, body)
        self.assertEqual(st, 200)
        st, _, gb, _ = self.app.handle("GET", "/api/report-settings", {"eng": "e1"}, b"")
        got = json.loads(gb)["findings"][str(fid)]["screenshots"]
        self.assertEqual(got, ["/tmp/a.png"])
```

- [ ] **Step 2: Run to verify status**

Run: `python3 -m unittest tests.test_web.WebTest.test_findings_expose_narrative_evidence tests.test_web.WebTest.test_finding_screenshot_slot_round_trips -v`
Expected: these likely PASS already (the endpoints exist) — they lock in the contract the UI relies on. If `/api/report-settings` GET returns a different envelope, adjust the assertion to match the real shape (read the handler at `atpt/web.py:497`). Proceed either way; they are regression guards for the UI work.

- [ ] **Step 3: Make findings rows clickable + render a detail panel (UI)**

In `atpt/web.py` `refreshFindings` (~line 1136), give each row a `data-fid` and a click handler, and add a detail container. Replace the row template so each `<tr>` carries `data-fid="${f.id}" style="cursor:pointer"`, then after building the table attach:

```javascript
  document.querySelectorAll('#findings tr[data-fid]').forEach(tr=>tr.onclick=()=>showFindingDetail(+tr.dataset.fid));
```

Add a `showFindingDetail(id)` function that finds the row in the already-fetched `findings`, fetches `/api/report-settings?eng=…` for its screenshots, and renders (all values `esc()`-escaped): title, severity, status, owasp, cvss, affected (`evidence.asset_value`), and the narrative fields `evidence.description`, `evidence.reproduction`, `evidence.impact`, `evidence.remediation`, `evidence.confidence`; then the screenshots as `<img>`; then an "Add screenshot" `<input type=file>` that calls the existing `uploadPicked(file)` and POSTs the returned path into `config.report.findings[id].screenshots` via `/api/report-settings` (merge with existing report-settings so other findings are preserved).

(This is client JS — verify by loading the console; the endpoint contracts are covered by Step 1.)

- [ ] **Step 4: Run the web suite**

Run: `python3 -m unittest tests.test_web -v`
Expected: PASS.

- [ ] **Step 5: Manual UI verification**

Run the app against a seeded engagement (e.g. `/api/demo` then add a director finding, or reuse an existing engagement), click a finding row, confirm the detail panel shows the narrative and lets you attach a screenshot that then appears in the report customization panel too.

- [ ] **Step 6: Commit**

```bash
git add atpt/web.py tests/test_web.py
git commit -m "feat(web): clickable finding detail with full write-up + shared screenshot slot"
```

---

### Task 8: Per-role ladder Settings UI (Item 7 UI)

**Files:**
- Modify: `atpt/web.py` (per-role section under the global ladder editor; include `roles` in the saved `reasoning` payload)
- Test: `tests/test_web_settings.py`

**Interfaces:**
- Consumes: Task 2's `reasoning.roles` config shape + `atpt.reasoning.ROLES`; existing `/api/settings` GET/POST, `_save_settings`, `_preserve_reasoning_keys`, `_redact_settings`, the JS `LADDER` editor (`renderLadder`, save at ~line 1532).
- Produces: Settings persists a `reasoning.roles` map (role → `{ladder:[{provider,model,effort}]}`) and returns it on GET; a role left on "use global" contributes no entry. No provider keys live under `roles`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_web_settings.py` (use its existing `WebApp` setup; mirror the `_post`/`_get` helpers from `test_web.py` if not present):

```python
    def test_reasoning_roles_persist_and_return(self):
        body = {"reasoning": {
            "providers": {"p1": {"backend": "cli", "cmd": "echo"}},
            "ladder": [{"provider": "p1"}],
            "roles": {"director": {"ladder": [{"provider": "p1", "model": "m1"}]}}}}
        self.app.handle("POST", "/api/settings", {}, json.dumps(body).encode())
        st, _, gb, _ = self.app.handle("GET", "/api/settings", {}, b"")
        got = json.loads(gb).get("reasoning", {})
        self.assertIn("director", got.get("roles", {}))
        self.assertEqual(got["roles"]["director"]["ladder"][0]["model"], "m1")
```

- [ ] **Step 2: Run to verify status**

Run: `python3 -m unittest tests.test_web_settings -v`
Expected: FAIL if `_redact_settings` or `_preserve_reasoning_keys` drops `roles`; PASS if `reasoning` is stored/returned wholesale. Read `_redact_settings` and `_preserve_reasoning_keys` (`atpt/web.py`) to confirm — they operate on `reasoning.providers` only, so `roles` should pass through. If the test fails because redaction rebuilds `reasoning` field-by-field, add `roles` to the fields it preserves.

- [ ] **Step 3: Ensure `roles` survives save/redact (only if Step 2 failed)**

If needed, in `_redact_settings` (and/or `_preserve_reasoning_keys`) make sure the `reasoning` dict copies `roles` through unchanged (it carries no secrets). Do not add redaction to it.

- [ ] **Step 4: Add the per-role UI + include `roles` in the save payload**

In `atpt/web.py`, below the existing global ladder editor block (the `#ladder` UI), add a per-role section that lists `director / osint / active_recon / skill / scope / map / exploit / report` (label `report` as "Report author/manager", `scope` as "Scope agent", `osint` as "OSINT / passive recon", `active_recon` as "Active recon"). Each role defaults to a "Use global ladder" checkbox; when unchecked ("Custom"), show a ladder editor scoped to that role reusing the same provider list. Maintain a JS `ROLE_LADDERS` object (role → `[{provider,model,effort}]`) populated from `SET.reasoning.roles` on load.

At the save site (~line 1532) where `const reasoning={providers:providersMap(),ladder:LADDER,preference:pref, …}` is built, add:

```javascript
roles: Object.fromEntries(Object.entries(ROLE_LADDERS)
        .filter(([r,l])=>l && l.length)
        .map(([r,l])=>[r,{ladder:l}])),
```

(so a role on "use global" contributes nothing). UI verified manually; the persistence contract is covered by Step 1.

- [ ] **Step 5: Run the settings tests**

Run: `python3 -m unittest tests.test_web_settings tests.test_web -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add atpt/web.py tests/test_web_settings.py
git commit -m "feat(web): per-role model-ladder editor in Settings (global + per-role overrides)"
```

---

### Task 10: OSINT phase — passive-recon expert (Item 8)

**Files:**
- Modify: `modules/agent_offensive/loop.py` (add `intel=""` param; seed the transcript)
- Modify: `modules/agent_offensive/module.py` (`_osint_summary` helper; run it before `run_loop`; pass its output as `intel`)
- Test: `tests/test_agent_loop.py`, `tests/test_agent_module.py`

**Interfaces:**
- Consumes: Task 2 role `osint`; `run_loop(...)`; `ctx.reason(prompt, phase, role="osint")`.
- Produces: `run_loop(..., intel="")` seeds the transcript with an `OSINT INTEL (passive recon):` block; `modules.agent_offensive.module._osint_summary(ctx, emit) -> str` runs an OSINT expert (phase `recon`, role `osint`) over operator context in `config.osint.context` (for THM/HTB the challenge-page text/URL), emits `agent_osint`, and its output is passed as `intel`. Recon is now two phases: passive OSINT → the active loop. (A fully separate active-recon agent is a possible follow-up; for now the loop's active recon runs under the director.)

- [ ] **Step 1: Write the failing test (loop intel)** — append to `tests/test_agent_loop.py` inside `LoopTest`:

```python
    def test_intel_seeds_transcript(self):
        seen = {}
        def rf(prompt):
            seen["p"] = prompt
            return '{"done": true}'
        run_loop(goal="x", guard=guard(), reason_fn=rf, max_steps=1,
                 emit=lambda *a, **k: None,
                 execute_fn=lambda a, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=lambda a, r: ([], []), intel="target runs WordPress 6.1")
        self.assertIn("OSINT INTEL", seen["p"])
        self.assertIn("WordPress 6.1", seen["p"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_agent_loop.LoopTest.test_intel_seeds_transcript -v`
Expected: FAIL — `run_loop()` has no `intel` keyword.

- [ ] **Step 3: Implement the loop seed**

In `modules/agent_offensive/loop.py`, add `intel=""` to the `run_loop` signature (after `distill_fn=None`), and right after `assets, findings, transcript = [], [], []` add:

```python
    if intel:
        transcript.append(f"OSINT INTEL (passive recon):\n{intel}")
```

- [ ] **Step 4: Run to verify pass**

Run: `python3 -m unittest tests.test_agent_loop.LoopTest.test_intel_seeds_transcript -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test (OSINT helper)** — append to `tests/test_agent_module.py`:

```python
    def test_osint_summary_uses_context_and_osint_role(self):
        import json
        from modules.agent_offensive.module import _osint_summary

        class _Ctx:
            engagement = {"id": "e", "config": json.dumps(
                {"osint": {"context": "Challenge page: login form, hint admin/admin"}})}
            scope = {"in_scope_domains": ["t.com"]}
            goals = "capture flags"
            def reason(self, prompt, phase, role=None):
                self.seen = (phase, role, prompt)
                return "LEAD: try admin/admin on the login form"

        ctx = _Ctx(); events = []
        out = _osint_summary(ctx, lambda *a, **k: events.append(a))
        self.assertIn("admin/admin", out)
        self.assertEqual(ctx.seen[0], "recon")
        self.assertEqual(ctx.seen[1], "osint")
        self.assertIn("Challenge page", ctx.seen[2])
```

- [ ] **Step 6: Run to verify failure**

Run: `python3 -m unittest tests.test_agent_module -v`
Expected: FAIL — no `_osint_summary`.

- [ ] **Step 7: Implement the OSINT helper + wire it**

In `modules/agent_offensive/module.py` add (module level):

```python
_OSINT_PROMPT = (
    "You are an OSINT / passive-reconnaissance expert. Using ONLY the context below "
    "(do not probe the target), summarise what is publicly known that helps the "
    "engagement goal: technologies, versions, endpoints, usernames/emails, credentials, "
    "and likely weak points. Be concise. If the context is a CTF challenge page, extract "
    "EVERY hint.\n\nGoal: {goal}\nIn-scope: {scope}\n\nContext:\n{context}\n")


def _osint_summary(ctx, emit) -> str:
    cfg = (json.loads(ctx.engagement.get("config") or "{}").get("osint") or {})
    context = str(cfg.get("context") or "").strip() or "(no OSINT context provided)"
    text = (ctx.reason(_OSINT_PROMPT.format(
        goal=ctx.goals or "(none stated)", scope=json.dumps(ctx.scope), context=context),
        "recon", role="osint") or "").strip()
    if text:
        emit("agent_osint", f"[agent] OSINT (passive recon) summary ({len(text)} chars)")
    return text
```

In `AgentOffensive.run`, immediately before the `run_loop(...)` call add `intel = _osint_summary(ctx, emit)` and pass `intel=intel` into `run_loop(...)`.

- [ ] **Step 8: Run to verify pass**

Run: `python3 -m unittest tests.test_agent_loop tests.test_agent_module -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add modules/agent_offensive/loop.py modules/agent_offensive/module.py tests/test_agent_loop.py tests/test_agent_module.py
git commit -m "feat(agent): OSINT passive-recon phase (role osint) feeds the director loop"
```

---

### Task 11: Conversational scope agent — backend (Item 9)

**Files:**
- Create: `modules/agent_scope/__init__.py`, `modules/agent_scope/agent.py`
- Modify: `atpt/state.py` (`set_scope`)
- Modify: `atpt/web.py` (`_validate_scope_payload` refactor; `_scope_reason_fn`; `/api/scope/chat`, `/api/scope/apply`)
- Test: `tests/test_agent_scope.py`, `tests/test_web.py`

**Interfaces:**
- Consumes: Task 2 role `scope`; existing `_derive_scope`, `_enabled_without_target`, `WebApp.handle`, `SQLiteStore`, the `_report_reason_fn` pattern from Task 6.
- Produces: `modules.agent_scope.agent.build_prompt(typed_scope, convo) -> str` and `extract_proposed_scope(text) -> dict|None`; `SQLiteStore.set_scope(eid, scope: dict)`; `POST /api/scope/chat` → `{reply, proposed_scope}`; `POST /api/scope/apply` (validates like create, then writes the engagement scope). SAFETY: apply runs the SAME validation as `_create_engagement`; the deterministic startup scope-confirm gate still runs before any scanning; the agent can never widen scope or approve for the operator.

- [ ] **Step 1: Write the failing tests (agent module)** — create `tests/test_agent_scope.py`:

```python
import unittest
from modules.agent_scope.agent import build_prompt, extract_proposed_scope


class ScopeAgentTest(unittest.TestCase):
    def test_confirm_prompt_when_typed_scope_present(self):
        p = build_prompt({"in_scope_domains": ["t.com"]}, [{"role": "user", "text": "hi"}])
        self.assertIn("already", p.lower())
        self.assertIn("t.com", p)

    def test_elicit_prompt_when_no_scope(self):
        p = build_prompt(None, [])
        self.assertIn("not", p.lower())
        self.assertIn("PROPOSED_SCOPE", p)

    def test_extract_proposed_scope(self):
        text = 'Sure. PROPOSED_SCOPE: {"in_scope_domains":["a.com"],"in_scope_cidrs":[],"out_of_scope":[]}\nApprove?'
        self.assertEqual(extract_proposed_scope(text)["in_scope_domains"], ["a.com"])

    def test_extract_none_when_absent(self):
        self.assertIsNone(extract_proposed_scope("just chatting, no proposal yet"))
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_agent_scope -v`
Expected: FAIL — `modules.agent_scope` does not exist.

- [ ] **Step 3: Implement the scope-agent module**

Create `modules/agent_scope/__init__.py` (empty). Create `modules/agent_scope/agent.py`:

```python
"""Scope agent: a plain-chat helper that restates a typed scope for confirmation, or
elicits a scope conversationally and proposes it. Pure prompt/parse logic — the web
layer supplies the reasoner and enforces validation + the deterministic gate."""
from __future__ import annotations
import json
import re

_CONFIRM = (
    "You are a scope agent for an AUTHORIZED penetration test. The operator has ALREADY "
    "defined this scope. Restate it in plain language, flag anything that looks like a "
    "typo or an unintentionally broad range, and ask them to confirm. Do NOT invent new "
    "targets.\n\nScope: {scope}\n\nConversation so far:\n{convo}\n")
_ELICIT = (
    "You are a scope agent for an AUTHORIZED penetration test. The operator has NOT "
    "defined a scope yet. Ask concise questions to establish the in-scope targets "
    "(domains, IPs, CIDRs) and anything explicitly out of scope. When you have enough, "
    "output a line 'PROPOSED_SCOPE: ' followed by a JSON object "
    '{{"in_scope_domains":[...],"in_scope_cidrs":[...],"out_of_scope":[...]}} and ask the '
    "operator to approve. NEVER guess targets they did not give.\n\n"
    "Conversation so far:\n{convo}\n")
_PROP = re.compile(r"PROPOSED_SCOPE:\s*(\{.*\})", re.S)


def build_prompt(typed_scope, convo) -> str:
    body = "\n".join(f"{m.get('role')}: {m.get('text')}" for m in (convo or []))
    if typed_scope:
        return _CONFIRM.format(scope=json.dumps(typed_scope), convo=body)
    return _ELICIT.format(convo=body)


def extract_proposed_scope(text):
    m = _PROP.search(text or "")
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None
```

- [ ] **Step 4: Run to verify pass**

Run: `python3 -m unittest tests.test_agent_scope -v`
Expected: PASS.

- [ ] **Step 5: Write the failing tests (web endpoints)** — append to `tests/test_web.py` inside `WebTest`:

```python
    def test_scope_apply_writes_valid_scope(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["old.com"]},
                                "e1.scope.json", "semi", {})
        body = json.dumps({"scope": {"domains": {"web": {"enabled": True, "in": ["new.com"]}}}}).encode()
        st, _, _, _ = self.app.handle("POST", "/api/scope/apply", {"eng": "e1"}, body)
        self.assertEqual(st, 200)
        sc = json.loads(SQLiteStore(self.db).get_engagement("e1")["scope"])
        self.assertIn("new.com", sc.get("in_scope_domains", []))

    def test_scope_apply_rejects_empty_target(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["old.com"]},
                                "e1.scope.json", "semi", {})
        body = json.dumps({"scope": {"domains": {"web": {"enabled": True, "in": []}}}}).encode()
        st, _, _, _ = self.app.handle("POST", "/api/scope/apply", {"eng": "e1"}, body)
        self.assertEqual(st, 400)

    def test_scope_chat_returns_shape(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["t.com"]},
                                "e1.scope.json", "semi", {})
        body = json.dumps({"typed_scope": {"in_scope_domains": ["t.com"]}, "messages": []}).encode()
        st, _, b, _ = self.app.handle("POST", "/api/scope/chat", {"eng": "e1"}, body)
        self.assertEqual(st, 200)
        d = json.loads(b)
        self.assertIn("reply", d)
        self.assertIn("proposed_scope", d)
```

- [ ] **Step 6: Run to verify failure**

Run: `python3 -m unittest tests.test_web -v`
Expected: FAIL — `/api/scope/*` routes 404.

- [ ] **Step 7: Implement the store method, validation refactor, reasoner helper, and routes**

In `atpt/state.py` (engagements section) add:

```python
    def set_scope(self, eid, scope: dict):
        self.cx.execute("UPDATE engagements SET scope=? WHERE id=?", (json.dumps(scope), eid))
        self.cx.commit()
```

In `atpt/web.py`, extract the create-time scope validation into a reusable method and have `_create_engagement` call it:

```python
    def _validate_scope_payload(self, raw_scope):
        scope = _derive_scope(raw_scope or {})
        empty = _enabled_without_target(raw_scope or {})
        if empty:
            return None, (f"selected scope {'categories' if len(empty) > 1 else 'category'} "
                          f"{', '.join(empty)} need a target — supply an in-scope host/IP/CIDR "
                          f"(or deselect it); a blank category is not scanned as the full domain")
        if not (scope.get("in_scope_domains") or scope.get("in_scope_cidrs")):
            return None, "scope must define at least one in-scope domain or CIDR (target required)"
        return scope, None
```

Add a scope reasoner helper (mirrors Task 6's `_report_reason_fn`):

```python
    def _scope_reason_fn(self, eid):
        store = self._store()
        eng = store.get_engagement(eid) or {}
        cfg = json.loads(eng.get("config") or "{}")
        rc = cfg.get("reasoning") or (store.get_settings() or {}).get("reasoning")
        if not rc:
            return None
        from .reasoning import ReasoningLadder
        ladder = ReasoningLadder(rc)
        def rf(prompt):
            res = ladder.reason(prompt, "scope", role="scope")
            return res.text if res else None
        return rf
```

Add the routes in `handle` (near the other engagement `/api/...` routes, where `eid` is already resolved):

```python
        if path == "/api/scope/chat" and method == "POST":
            from modules.agent_scope.agent import build_prompt, extract_proposed_scope
            rf = self._scope_reason_fn(eid)
            reply = rf(build_prompt(data.get("typed_scope"), data.get("messages") or [])) if rf else ""
            reply = reply or ""
            return self._json(200, {"reply": reply, "proposed_scope": extract_proposed_scope(reply)})
        if path == "/api/scope/apply" and method == "POST":
            scope, err = self._validate_scope_payload(data.get("scope") or {})
            if err:
                return self._json(400, {"error": err})
            store.set_scope(eid, scope)
            store.add_event(eid, "scope", None, "info", "scope_set",
                            "scope written via scope agent (pending startup confirmation)", None)
            return self._json(200, {"scope": scope})
```

- [ ] **Step 8: Run to verify pass**

Run: `python3 -m unittest tests.test_agent_scope tests.test_web -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add modules/agent_scope/ atpt/state.py atpt/web.py tests/test_agent_scope.py tests/test_web.py
git commit -m "feat(scope): conversational scope agent backend (chat + validated apply); deterministic gate unchanged"
```

---

### Task 12: Scope-agent chat UI (Item 9)

**Files:**
- Modify: `atpt/web.py` (Scope chat panel: messages + send → `/api/scope/chat`; "Approve & write scope" → `/api/scope/apply`; on start with a typed scope, open with the agent's restatement)
- Test: manual UI; backend covered by Task 11.

**Interfaces:**
- Consumes: Task 11's `/api/scope/chat`, `/api/scope/apply`.
- Produces: a chat-style scope setup in the console. Mode A (scope typed in the form) → the agent restates it and asks approval; Mode B (no scope) → the agent elicits scope and, on approval, writes it. The deterministic startup confirmation still gates the run.

- [ ] **Step 1: Add the scope-chat widget to the Scope panel**

In the Settings→Scope panel (the `loadScope` area of `atpt/web.py`), add a chat widget below the existing scope form:

```html
<div id="scope_chat" class="chat" style="max-height:220px;overflow:auto"></div>
<div class="row">
  <input id="scope_msg" placeholder="Describe or confirm your scope…">
  <button id="scope_send">Send</button>
  <button id="scope_apply" class="ghost">Approve &amp; write scope</button>
</div>
```

- [ ] **Step 2: Wire the chat JS**

Add, adapting selectors and the `api()` helper to the existing web JS conventions:

```javascript
let SCOPE_MSGS = [], SCOPE_PROPOSED = null;
function currentTypedScope(){ /* return the scope form payload if the operator filled it, else null */ return null; }
function renderScopeChat(){ $('#scope_chat').innerHTML = SCOPE_MSGS.map(m=>
  `<div class="msg ${esc(m.role)}">${esc(m.text)}</div>`).join(''); }
async function scopeSend(){
  const t=$('#scope_msg').value.trim(); if(t){ SCOPE_MSGS.push({role:'user',text:t}); }
  $('#scope_msg').value='';
  const r=await api('/api/scope/chat?eng='+encodeURIComponent(ENG),{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({typed_scope:currentTypedScope(),messages:SCOPE_MSGS})});
  if(r.reply){ SCOPE_MSGS.push({role:'assistant',text:r.reply}); }
  if(r.proposed_scope){ SCOPE_PROPOSED=r.proposed_scope; }
  renderScopeChat();
}
async function scopeApply(){
  const scope = SCOPE_PROPOSED || currentTypedScope();
  if(!scope){ SCOPE_MSGS.push({role:'assistant',text:'No scope to write yet — describe it first.'}); renderScopeChat(); return; }
  const r=await api('/api/scope/apply?eng='+encodeURIComponent(ENG),{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({scope})});
  if(r.error){ SCOPE_MSGS.push({role:'assistant',text:'⚠ '+r.error}); renderScopeChat(); return; }
  SCOPE_MSGS.push({role:'assistant',text:'Scope written. It will be confirmed again before scanning starts.'});
  renderScopeChat(); loadScope();
}
$('#scope_send')&&($('#scope_send').onclick=scopeSend);
$('#scope_apply')&&($('#scope_apply').onclick=scopeApply);
```

- [ ] **Step 3: Manual verification**

Run the app, open Scope, chat to define or confirm a scope, click Approve, confirm the engagement scope updates and the deterministic startup confirmation still appears when a run starts.

- [ ] **Step 4: Commit**

```bash
git add atpt/web.py
git commit -m "feat(web): scope-agent chat panel (define/confirm scope in plain chat)"
```

---

### Task 13: Full-suite green + docs

**Files:**
- Modify: `README.md` (director-as-default engine, rich findings + clickable detail, LLM report, per-role ladders)
- Test: whole suite

**Interfaces:**
- Consumes: everything above.
- Produces: a green full suite and user-facing docs reflecting the new behavior.

- [ ] **Step 1: Run the whole suite**

Run: `python3 -m pytest -q tests/`
Expected: all green (baseline ≈312 + the tests added here), 0 warnings. Fix any regression before proceeding.

- [ ] **Step 2: Update the README**

Document, briefly: the LLM Director is the default engine (classic pipeline selectable); findings are authored by the director with full write-ups; the findings table is clickable to a detail view with operator-attached screenshots; the PTES report's executive summary + methodology are written by an LLM from the real run (deterministic template when no model is configured); model ladders are configurable globally and per role, with any provider usable for any role (nothing pinned to a specific model); recon runs as two phases (a passive OSINT expert then active recon); and scope can be set or confirmed by chatting with a scope agent (the deterministic gate still confirms before scanning).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): LLM director default, rich findings + detail view, LLM report, per-role ladders"
```

---

### Task 14: OSINT context input — make the OSINT phase reachable (Item 8 completion)

**Files:**
- Modify: `atpt/web.py` (CTF panel textarea; `_get_ctf` returns it; `_save_ctf` persists it to `config.osint.context`; loadCtf/saveCtf JS)
- Modify: `README.md` (name where to set the OSINT context)
- Test: `tests/test_web_settings.py`

**Interfaces:**
- Consumes: Task 10's `_osint_summary` (reads `config.osint.context`); existing `_get_ctf`/`_save_ctf`/`update_engagement_config`; the CTF settings panel + its loadCtf/saveCtf JS.
- Produces: an "OSINT context / challenge page" textarea in Settings→CTF that persists to `config.osint.context` (top-level, mirroring how `_save_ctf` stores `offensive_agent`), so the passive OSINT phase (Task 10) actually has input. `_get_ctf` returns `osint` for pre-fill.

- [ ] **Step 1: Write the failing test** — append to `tests/test_web_settings.py` (mirror its setUp: `WebApp(".", db_path=self.db)`; import `SQLiteStore`):

```python
    def test_ctf_saves_osint_context(self):
        import json as _j
        self.app.handle("POST", "/api/engagement", {}, _j.dumps({
            "engagement": "o1", "mode": "semi",
            "scope": {"domains": {"web": {"enabled": True, "in": ["t.com"]}}}}).encode())
        self.app.handle("POST", "/api/settings/ctf", {"eng": "o1"},
                        _j.dumps({"osint_context": "Challenge: login form, hint admin/admin"}).encode())
        cfg = _j.loads(SQLiteStore(self.db).get_engagement("o1")["config"])
        self.assertEqual(cfg["osint"]["context"], "Challenge: login form, hint admin/admin")
        st, _, gb, _ = self.app.handle("GET", "/api/settings/ctf", {"eng": "o1"}, b"")
        self.assertEqual(_j.loads(gb).get("osint", {}).get("context"), "Challenge: login form, hint admin/admin")
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_web_settings -v`
Expected: FAIL — `_save_ctf` ignores `osint_context` and `_get_ctf` returns no `osint`.

- [ ] **Step 3: Implement the backend**

In `atpt/web.py` `_get_ctf`, before `return ctf` add:

```python
        ctf["osint"] = cfg.get("osint") or {}
```

In `_save_ctf`, after the `offensive_agent` block (before `return`), add:

```python
        if "osint_context" in data:
            store.update_engagement_config(eid, {"osint": {"context": str(data.get("osint_context") or "")}})
```

- [ ] **Step 4: Add the CTF-panel field + JS wiring**

In the CTF panel HTML (`data-panel="ctf"`), after the Goals `<label>` add:

```html
          <label class="hint full">OSINT context / challenge page — text the passive-recon (OSINT) phase reasons over<textarea id="c_osint" rows="4" placeholder="Paste the THM/HTB challenge page, or any known public info about the target"></textarea></label>
```

In `loadCtf` (where it fills `#c_goals` from the GET response `c`), add:

```javascript
  $('#c_osint').value=(c.osint||{}).context||'';
```

In `saveCtf` (the body it POSTs to `/api/settings/ctf`), add `osint_context:$('#c_osint').value` to the payload object.

- [ ] **Step 5: Run to verify pass**

Run: `python3 -m unittest tests.test_web_settings -v`
Expected: PASS.

- [ ] **Step 6: Name the field in the README**

In `README.md`, extend the OSINT sentence to point operators to the field, e.g. append: "— paste it in **☰ → Scope → CTF / engagement → OSINT context**."

- [ ] **Step 7: Full suite green + commit**

Run: `python3 -m pytest -q tests/` (expect green).

```bash
git add atpt/web.py README.md tests/test_web_settings.py
git commit -m "feat(web): OSINT context input in CTF settings — feeds the passive-recon phase (completes Item 8)"
```

---

## Self-Review

**Spec coverage:**
- Item 1 (director-as-engine default + toggle) → Task 5. ✅
- Item 2 (finding action) → Task 4. ✅
- Item 3 (LLM report + `list_events`) → Task 3 (`list_events`) + Task 6. ✅
- Item 4 (rich findings stored, evidence-JSON, no migration) → Task 3 (round-trip test) + Task 4 (writes the shape). ✅
- Item 5 (clickable detail + screenshots) → Task 7. ✅
- Item 6 (ladder error-shaped fallback) → Task 1. ✅
- Item 7 (per-role ladders: backend + role threading, UI) → Task 2 (backend) + Task 8 (UI). ✅
- Item 8 (recon split) → Task 10 (OSINT phase); `active_recon` role registered in Task 2. Active recon runs under the director loop for now; a fully separate active-recon agent is a noted follow-up. ✅
- Item 9 (conversational scope agent) → Task 11 (backend) + Task 12 (UI); deterministic scope wall + startup confirmation unchanged. ✅
- Item 11 (debugger agent) → deferred to its own spec+plan (operator decision, 2026-09-19). Not in this plan.
- Safety unchanged (D-safety): no task touches `guard.py`/`scope.py`/approval gating; the `finding` action runs no command; the report pass only reads/writes prose. ✅
- Model-agnostic (D6): no provider/model hardcoded; the report reason_fn returns None → template. ✅

**Placeholder scan:** every code step carries real code; every test step carries assertions; no TBD/TODO. Web-only JS steps (Tasks 5/7/8/12) pair the manual UI change with a backend test that locks the contract. ✅

**Type consistency:**
- `reason(prompt, phase, role=None)` — defined in Task 2, used in Tasks 2/6; `ctx.reason(..., role=...)` consistent across `agent_offensive`, `map_ptt`, `exploit_hbgpt`, `report_ptes`, `web`. ✅
- `build_report_md(store, eid, project_dir, reason_fn=None)` — defined Task 6, called with the new arg in the module and web; 3-arg legacy calls (`test_report_author.py`) still valid via the default. ✅
- Finding dict shape (`evidence.{asset_value,description,reproduction,impact,remediation,confidence}`, `source_tool:"agent-director"`) — written in Task 4, round-tripped in Task 3, read by the report (Task 6) and the detail view (Task 7). ✅
- `list_events(eid)` — defined Task 3, consumed Task 6. ✅
- `ROLES` — defined Task 2, consumed by the UI (Task 8). ✅

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, two-stage review between tasks, controller commits each task's staged work.
2. **Inline Execution** — execute tasks in this session with checkpoints.

(Per the agreed workflow this will be subagent-driven-development.)
