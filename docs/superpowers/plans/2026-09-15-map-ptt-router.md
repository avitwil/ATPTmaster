# Map/PTT Router + Reasoning Ladder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `map` phase module (`map_ptt`) that turns discovered assets into prioritized candidate findings, plus the framework-wide reasoning ladder (`atpt/reasoning.py`) it consumes.

**Architecture:** Deterministic rules map `asset → candidate finding` with no model required; an optional reasoning ladder (registered providers, preference order, fallback-on-refusal/error) enriches them via `ctx.reason(...)`. The map module producing the `finding` token unblocks the downstream exploit/validate pipeline.

**Tech Stack:** Python 3 stdlib only (`sqlite3`, `urllib.request`, `subprocess`, `unittest`). No third-party packages.

**Spec:** `docs/superpowers/specs/2026-09-15-map-ptt-router-design.md`

## Global Constraints

- **Stdlib-only.** No third-party imports anywhere in `atpt/` or `modules/`. HTTP via `urllib.request`, subprocess via `subprocess`.
- **Tests use `unittest`.** Run the suite with `python3 -m unittest discover -s tests` (or `python3 -m unittest tests.test_core`). No pytest.
- **No real providers/tools executed in tests.** Every network/CLI/subprocess call is monkeypatched. Consistent with "nothing vendored is executed."
- **Secrets from env vars only.** API keys referenced by `key_env` name, read via `os.environ` at call time; never stored in the DB, never in a URL, never logged.
- **No guardrail-bypass tooling.** A refusal advances the ladder to the next provider; prompts are never rewritten to defeat a model's guardrails.
- **Module IDs sort by phase then id.** Keep `map_ptt` non-intrusive (`intrusive: false`).
- **Existing 4 tests in `tests/test_core.py` must stay green** after every task.

---

### Task 0: Prerequisites & baseline

**Files:** none created.

- [ ] **Step 1: (Optional) initialize git so commits work**

The working dir is not a git repo. If you want the per-task commits below, run once:
```bash
cd /home/avi/Projects/claude_projects/ATPTmaster
git init && git add -A && git commit -m "chore: baseline before map_ptt"
```
If the operator prefers no git, skip every "Commit" step in this plan.

- [ ] **Step 2: Confirm the baseline suite passes**

Run: `python3 -m unittest tests.test_core -v`
Expected: `Ran 4 tests ... OK`

---

### Task 1: `list_assets` read API on the store

**Files:**
- Modify: `atpt/state.py` (add method near `count_assets`, ~line 113)
- Test: `tests/test_state_assets.py`

**Interfaces:**
- Produces: `SQLiteStore.list_assets(eid) -> list[dict]` — asset rows including the integer `id` column, ordered by `id`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_state_assets.py`:
```python
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore


class ListAssetsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {}, "s.json", "full", {})

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_assets_returns_rows_with_id(self):
        self.store.upsert_asset("E", {"asset_type": "service", "value": "h1:22",
                                      "service": "ssh", "port": 22})
        rows = self.store.list_assets("E")
        self.assertEqual(len(rows), 1)
        self.assertIn("id", rows[0])
        self.assertIsInstance(rows[0]["id"], int)
        self.assertEqual(rows[0]["service"], "ssh")

    def test_list_assets_scoped_to_engagement(self):
        self.store.create_engagement("F", "F", {}, "s.json", "full", {})
        self.store.upsert_asset("E", {"asset_type": "host", "value": "a"})
        self.store.upsert_asset("F", {"asset_type": "host", "value": "b"})
        self.assertEqual([r["value"] for r in self.store.list_assets("E")], ["a"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_state_assets -v`
Expected: FAIL — `AttributeError: 'SQLiteStore' object has no attribute 'list_assets'`

- [ ] **Step 3: Add the method**

In `atpt/state.py`, directly after `count_assets` (before `count_findings`):
```python
    def list_assets(self, eid) -> list[dict]:
        return [dict(r) for r in self.cx.execute(
            "SELECT * FROM assets WHERE engagement_id=? ORDER BY id", (eid,))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_state_assets tests.test_core -v`
Expected: PASS — all tests OK.

- [ ] **Step 5: Commit**

```bash
git add atpt/state.py tests/test_state_assets.py
git commit -m "feat(state): add list_assets read API"
```

---

### Task 2: Reasoning ladder core (dispatch, policy, refusal)

**Files:**
- Create: `atpt/reasoning.py`
- Test: `tests/test_reasoning.py`

**Interfaces:**
- Produces:
  - `ReasoningResult` dataclass: `text: str`, `provider: str`, `status: str = "ok"`.
  - `ReasoningLadder(config: dict | None, emit=None)` with `reason(prompt: str, phase: str) -> ReasoningResult | None`.
  - `BACKENDS: dict[str, callable]` — name → `fn(provider_cfg: dict, prompt: str) -> str` (real backends filled in Task 3; tests monkeypatch this dict).
  - `_is_refusal(text: str) -> bool`.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reasoning.py`:
```python
import unittest

from atpt import reasoning
from atpt.reasoning import ReasoningLadder, _is_refusal


CFG = {
    "providers": {
        "p1": {"backend": "fake"},
        "p2": {"backend": "fake"},
        "local": {"backend": "ollama"},
    },
    "preference": ["p1", "p2", "local"],
    "policy": {"map": "any", "secret": "local_only"},
}


class ReasoningLadderTest(unittest.TestCase):
    def setUp(self):
        self._saved = dict(reasoning.BACKENDS)

    def tearDown(self):
        reasoning.BACKENDS.clear()
        reasoning.BACKENDS.update(self._saved)

    def _install(self, fake, ollama=None):
        reasoning.BACKENDS.clear()
        reasoning.BACKENDS["fake"] = fake
        reasoning.BACKENDS["ollama"] = ollama or (lambda cfg, p: "OLLAMA-OK")

    def test_first_ok_wins(self):
        self._install(lambda cfg, p: "OK")
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "OK")
        self.assertEqual(res.provider, "p1")

    def test_refusal_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            return "I can't help with that." if len(calls) == 1 else "SECOND-OK"
        self._install(fake)
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "SECOND-OK")
        self.assertEqual(res.provider, "p2")

    def test_error_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return "RECOVERED"
        self._install(fake)
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "RECOVERED")

    def test_exhausted_returns_none(self):
        self._install(lambda cfg, p: "I cannot assist",
                      ollama=lambda cfg, p: "against my guidelines")
        self.assertIsNone(ReasoningLadder(CFG).reason("hi", "map"))

    def test_policy_local_only_skips_hosted(self):
        self._install(lambda cfg, p: "HOSTED", ollama=lambda cfg, p: "LOCAL")
        res = ReasoningLadder(CFG).reason("hi", "secret")
        self.assertEqual(res.text, "LOCAL")
        self.assertEqual(res.provider, "local")

    def test_empty_config_returns_none(self):
        self.assertIsNone(ReasoningLadder(None).reason("hi", "map"))

    def test_is_refusal(self):
        self.assertTrue(_is_refusal(""))
        self.assertTrue(_is_refusal("I'm unable to help"))
        self.assertFalse(_is_refusal("Sure, here are the findings"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_reasoning -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'atpt.reasoning'`

- [ ] **Step 3: Create the ladder (backends are placeholders until Task 3)**

Create `atpt/reasoning.py`:
```python
"""Provider ladder: try registered reasoning providers in preference order,
falling back to the next on refusal or error. Stdlib-only.

A refusal ADVANCES the ladder to the next provider (ultimately a local model the
operator runs themselves) — we never rewrite a prompt to defeat a model's
guardrails. Exhaustion returns None so callers fall back to deterministic logic.
"""
from __future__ import annotations
from dataclasses import dataclass

REFUSAL_MARKERS = (
    "i can't help", "i cannot help", "i can't assist", "i cannot assist",
    "i'm unable to", "i am unable to", "i won't", "i will not",
    "against my guidelines", "cannot comply", "can't comply",
)


def _is_refusal(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    return any(m in t for m in REFUSAL_MARKERS)


# Real backends are registered in Task 3. Tests monkeypatch this dict.
BACKENDS: dict = {}


@dataclass
class ReasoningResult:
    text: str
    provider: str
    status: str = "ok"


class ReasoningLadder:
    def __init__(self, config: dict | None, emit=None):
        cfg = config or {}
        self.providers: dict = cfg.get("providers", {})
        self.preference: list = cfg.get("preference", [])
        self.policy: dict = cfg.get("policy", {})
        self._emit = emit or (lambda *a, **k: None)

    def _allowed(self, provider_cfg: dict, phase: str) -> bool:
        pol = self.policy.get(phase, "any")
        if pol == "local_only":
            return provider_cfg.get("backend") == "ollama"
        return True  # "any" / "hosted_ok" / unknown -> permit

    def reason(self, prompt: str, phase: str) -> "ReasoningResult | None":
        for name in self.preference:
            pc = self.providers.get(name)
            if not pc or not self._allowed(pc, phase):
                continue
            backend = BACKENDS.get(pc.get("backend"))
            if backend is None:
                continue
            try:
                text = backend(pc, prompt)
            except Exception as exc:
                self._emit("reasoning_error", f"provider '{name}' error: {exc}", "warn")
                continue
            if _is_refusal(text):
                self._emit("reasoning_refused", f"provider '{name}' refused; advancing", "info")
                continue
            return ReasoningResult(text=text, provider=name)
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_reasoning tests.test_core -v`
Expected: PASS — all OK.

- [ ] **Step 5: Commit**

```bash
git add atpt/reasoning.py tests/test_reasoning.py
git commit -m "feat(reasoning): provider ladder with refusal/error fallback"
```

---

### Task 3: Concrete backends (cli / http_api / ollama)

**Files:**
- Modify: `atpt/reasoning.py` (add backend functions + populate `BACKENDS`)
- Test: `tests/test_reasoning_backends.py`

**Interfaces:**
- Produces (module-level functions in `atpt/reasoning.py`):
  - `_backend_cli(cfg, prompt) -> str`
  - `_backend_http_api(cfg, prompt) -> str`
  - `_backend_ollama(cfg, prompt) -> str`
  - `_extract_text(data: dict) -> str`
  - `BACKENDS = {"cli": _backend_cli, "http_api": _backend_http_api, "ollama": _backend_ollama}`

- [ ] **Step 1: Write the failing test**

Create `tests/test_reasoning_backends.py`:
```python
import types
import unittest

from atpt import reasoning
from atpt.reasoning import _backend_http_api, _backend_ollama, _extract_text, BACKENDS


class BackendsTest(unittest.TestCase):
    def test_registry_wired(self):
        self.assertEqual(set(BACKENDS), {"cli", "http_api", "ollama"})

    def test_extract_text_shapes(self):
        self.assertEqual(_extract_text({"response": "r"}), "r")
        self.assertEqual(_extract_text({"content": [{"text": "c"}]}), "c")
        self.assertEqual(
            _extract_text({"choices": [{"message": {"content": "m"}}]}), "m")

    def test_http_api_missing_key_raises(self):
        cfg = {"endpoint": "http://x", "model": "m", "key_env": "DEFINITELY_UNSET_KEY_XZ"}
        with self.assertRaises(RuntimeError):
            _backend_http_api(cfg, "hi")

    def test_ollama_parses_response(self):
        class _Resp:
            def read(self): return b'{"response": "hello"}'
            def __enter__(self): return self
            def __exit__(self, *a): return False
        orig = reasoning.urllib.request.urlopen
        reasoning.urllib.request.urlopen = lambda req, timeout=None: _Resp()
        try:
            self.assertEqual(_backend_ollama({"model": "m"}, "hi"), "hello")
        finally:
            reasoning.urllib.request.urlopen = orig
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_reasoning_backends -v`
Expected: FAIL — `ImportError: cannot import name '_backend_http_api'`

- [ ] **Step 3: Add the backends**

In `atpt/reasoning.py`, add imports at the top (below `from dataclasses import dataclass`):
```python
import json
import os
import subprocess
import urllib.request
```
Then add the backend functions ABOVE the `BACKENDS: dict = {}` line, and replace that line with the populated registry:
```python
def _extract_text(data: dict) -> str:
    if isinstance(data, dict):
        if "response" in data:
            return data["response"] or ""
        if "content" in data:
            c = data["content"]
            if isinstance(c, list) and c and isinstance(c[0], dict):
                return c[0].get("text", "")
            return str(c)
        if data.get("choices"):
            return data["choices"][0].get("message", {}).get("content", "")
    return ""


def _backend_cli(cfg: dict, prompt: str) -> str:
    cmd = cfg.get("cmd")
    if not cmd:
        raise ValueError("cli backend requires 'cmd'")
    proc = subprocess.run(cmd.split() + [prompt], capture_output=True,
                          text=True, timeout=cfg.get("timeout", 120))
    if proc.returncode != 0:
        raise RuntimeError(f"cli exit {proc.returncode}: {proc.stderr[-200:]}")
    return proc.stdout


def _backend_http_api(cfg: dict, prompt: str) -> str:
    key_env = cfg.get("key_env")
    key = os.environ.get(key_env) if key_env else None
    if key_env and not key:
        raise RuntimeError(f"missing API key env var '{key_env}'")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = json.dumps({"model": cfg.get("model"), "prompt": prompt}).encode()
    req = urllib.request.Request(cfg["endpoint"], data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 120)) as resp:
        return _extract_text(json.loads(resp.read().decode()))


def _backend_ollama(cfg: dict, prompt: str) -> str:
    url = cfg.get("endpoint", "http://localhost:11434/api/generate")
    body = json.dumps({"model": cfg.get("model", "llama3.1"),
                       "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 300)) as resp:
        return json.loads(resp.read().decode()).get("response", "")


BACKENDS: dict = {"cli": _backend_cli, "http_api": _backend_http_api,
                  "ollama": _backend_ollama}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_reasoning_backends tests.test_reasoning tests.test_core -v`
Expected: PASS — all OK (Task 2 tests still pass; they overwrite `BACKENDS` in setUp/tearDown).

- [ ] **Step 5: Commit**

```bash
git add atpt/reasoning.py tests/test_reasoning_backends.py
git commit -m "feat(reasoning): cli/http_api/ollama backends"
```

---

### Task 4: Wire `ctx.reason` into RunContext + engine

**Files:**
- Modify: `atpt/module.py` (`RunContext` dataclass, ~lines 54-65)
- Modify: `atpt/engine.py` (`_ctx`, ~lines 56-58; add import)
- Test: `tests/test_ctx_reason.py`

**Interfaces:**
- Produces: `RunContext.reasoner` (attribute, default `None`) and `RunContext.reason(prompt: str, phase: str) -> str | None`.
- Consumes: `atpt.reasoning.ReasoningLadder` (Task 2).

- [ ] **Step 1: Write the failing test**

Create `tests/test_ctx_reason.py`:
```python
import unittest
from pathlib import Path

from atpt.module import RunContext
from atpt.reasoning import ReasoningLadder, ReasoningResult


class _FakeLadder:
    def __init__(self, result):
        self._result = result

    def reason(self, prompt, phase):
        return self._result


class CtxReasonTest(unittest.TestCase):
    def _ctx(self, reasoner):
        return RunContext(engagement={"id": "E"}, scope={}, store=None,
                          project_dir=Path("."), dry_run=False, reasoner=reasoner)

    def test_reason_returns_text_when_ladder_answers(self):
        ctx = self._ctx(_FakeLadder(ReasoningResult(text="ANS", provider="p1")))
        self.assertEqual(ctx.reason("hi", "map"), "ANS")

    def test_reason_none_when_ladder_exhausted(self):
        ctx = self._ctx(_FakeLadder(None))
        self.assertIsNone(ctx.reason("hi", "map"))

    def test_reason_none_when_no_reasoner(self):
        ctx = self._ctx(None)
        self.assertIsNone(ctx.reason("hi", "map"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_ctx_reason -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'reasoner'`

- [ ] **Step 3: Add the field + method to RunContext**

In `atpt/module.py`, extend the `RunContext` dataclass. Add the field after `dry_run: bool = False`:
```python
    reasoner: Any = None
```
Then add a method (below `emit`):
```python
    def reason(self, prompt: str, phase: str) -> "str | None":
        if self.reasoner is None:
            return None
        res = self.reasoner.reason(prompt, phase)
        return res.text if res else None
```
(`Any` is already imported in `module.py`.)

- [ ] **Step 4: Wire the ladder in the engine**

In `atpt/engine.py`, add the import near the top:
```python
from .reasoning import ReasoningLadder
```
Replace `_ctx` (lines ~56-58) with:
```python
    def _ctx(self, eng: dict, dry_run: bool) -> RunContext:
        cfg = json.loads(eng.get("config") or "{}")
        reasoner = ReasoningLadder(
            cfg.get("reasoning"),
            emit=lambda kind, msg, lvl: self.store.add_event(
                eng["id"], None, None, lvl, kind, msg, None))
        return RunContext(engagement=eng, scope=json.loads(eng.get("scope") or "{}"),
                          store=self.store, project_dir=self.project_dir,
                          dry_run=dry_run, reasoner=reasoner)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_ctx_reason tests.test_core -v`
Expected: PASS — all OK (engine still builds RunContext correctly for the existing 4 tests).

- [ ] **Step 6: Commit**

```bash
git add atpt/module.py atpt/engine.py tests/test_ctx_reason.py
git commit -m "feat(core): expose ctx.reason backed by the reasoning ladder"
```

---

### Task 5: Deterministic rule set (`rules.py`)

**Files:**
- Create: `modules/map_ptt/rules.py`
- Test: `tests/test_map_rules.py`

**Interfaces:**
- Produces: `map_assets(assets: list[dict]) -> list[dict]` — candidate finding dicts, deduped on `(asset_id, title)`, sorted by `evidence.priority` descending. Each candidate has keys: `asset_id, title, domain, owasp, severity, cvss, status="candidate", source_tool="map_ptt", evidence={asset_value, rule, priority, provenance="rules"}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_map_rules.py`:
```python
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "map_ptt_rules", Path("modules/map_ptt/rules.py"))
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)


class MapRulesTest(unittest.TestCase):
    def test_ssh_service_maps_to_credential_candidate(self):
        out = rules.map_assets([{"id": 1, "asset_type": "service",
                                 "value": "h:22", "service": "ssh", "port": 22}])
        self.assertEqual(len(out), 1)
        c = out[0]
        self.assertEqual(c["asset_id"], 1)
        self.assertEqual(c["domain"], "Infra")
        self.assertEqual(c["owasp"], "A07")
        self.assertEqual(c["status"], "candidate")
        self.assertEqual(c["source_tool"], "map_ptt")
        self.assertEqual(c["evidence"]["provenance"], "rules")

    def test_data_service_is_high_severity(self):
        out = rules.map_assets([{"id": 2, "asset_type": "service",
                                 "value": "h:6379", "service": "redis"}])
        self.assertTrue(any(c["severity"] == "high" for c in out))

    def test_sensitive_web_path(self):
        out = rules.map_assets([{"id": 3, "asset_type": "web_path",
                                 "value": "http://h/admin", "url": "http://h/admin"}])
        self.assertTrue(any("path" in c["title"].lower() for c in out))

    def test_dedupe_on_asset_and_title(self):
        a = {"id": 4, "asset_type": "service", "value": "h:22",
             "service": "ssh", "port": 22}
        out = rules.map_assets([a, dict(a)])
        titles = [c["title"] for c in out if c["asset_id"] == 4]
        self.assertEqual(len(titles), len(set(titles)))

    def test_sorted_by_priority_desc(self):
        out = rules.map_assets([
            {"id": 5, "asset_type": "service", "value": "h:6379", "service": "redis"},
            {"id": 6, "asset_type": "web_endpoint", "value": "http://h", "url": "http://h"},
        ])
        prios = [c["evidence"]["priority"] for c in out]
        self.assertEqual(prios, sorted(prios, reverse=True))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_map_rules -v`
Expected: FAIL — `FileNotFoundError` / cannot load `modules/map_ptt/rules.py`.

- [ ] **Step 3: Create the rule set**

Create `modules/map_ptt/rules.py`:
```python
"""Deterministic asset -> candidate-finding mapping — the PTT decomposition
expressed as rules. Pure functions, no I/O. Each rule returns zero or more
candidate finding dicts; map_assets() runs them all, dedupes, and ranks."""
from __future__ import annotations

SENSITIVE_PATHS = ("/admin", "/login", "/.git", "/.env", "/actuator",
                   "/config", "/backup", "/phpmyadmin", "/wp-admin")
DATA_SERVICES = ("mysql", "postgres", "postgresql", "redis", "mongo",
                 "mongodb", "mssql", "oracle", "elasticsearch", "memcached")
CLEARTEXT_SERVICES = ("ftp", "telnet")


def _cand(asset, title, domain, owasp, severity, cvss, rule, priority):
    return {"asset_id": asset.get("id"), "title": title, "domain": domain,
            "owasp": owasp, "severity": severity, "cvss": cvss,
            "status": "candidate", "source_tool": "map_ptt",
            "evidence": {"asset_value": asset.get("value"), "rule": rule,
                         "priority": priority, "provenance": "rules"}}


def _svc(a):
    return (a.get("service") or "").lower()


def _rule_ssh(a):
    if _svc(a) == "ssh" or a.get("port") == 22:
        return [_cand(a, "SSH credential attack surface", "Infra", "A07",
                      "medium", 5.3, "ssh_surface", 60)]
    return []


def _rule_cleartext(a):
    if _svc(a) in CLEARTEXT_SERVICES:
        return [_cand(a, f"Cleartext service exposed ({_svc(a)})", "Infra", "A02",
                      "medium", 5.9, "cleartext_service", 55)]
    return []


def _rule_data_service(a):
    if _svc(a) in DATA_SERVICES:
        return [_cand(a, f"Exposed data service ({_svc(a)})", "Infra", "A05",
                      "high", 7.5, "exposed_data_service", 82)]
    return []


def _rule_web_known_tech(a):
    if a.get("asset_type") != "web_endpoint":
        return []
    tech = a.get("tech")
    techs = tech if isinstance(tech, list) else ([tech] if tech else [])
    out = []
    for t in techs:
        if t:
            out.append(_cand(a, f"Known-CVE candidate ({t})", "Web", "A06",
                             "high", 7.0, "known_tech", 78))
    return out


def _rule_sensitive_path(a):
    if a.get("asset_type") != "web_path":
        return []
    url = (a.get("url") or a.get("value") or "").lower()
    for p in SENSITIVE_PATHS:
        if p in url:
            return [_cand(a, f"Sensitive path exposed ({p})", "Web", "A05",
                          "high", 7.5, "sensitive_path", 80)]
    return []


def _rule_auth_protected(a):
    if a.get("http_status") in (401, 403):
        return [_cand(a, "Auth-protected surface (bypass candidate)", "Web", "A01",
                      "medium", 5.0, "auth_protected", 50)]
    return []


def _rule_web_generic(a):
    if a.get("asset_type") == "web_endpoint":
        return [_cand(a, "Web app entry (injection/XSS surface)", "Web", "A03",
                      "low", 3.5, "web_generic", 30)]
    return []


RULES = [_rule_ssh, _rule_cleartext, _rule_data_service, _rule_web_known_tech,
         _rule_sensitive_path, _rule_auth_protected, _rule_web_generic]


def map_assets(assets: list[dict]) -> list[dict]:
    out, seen = [], set()
    for a in assets:
        for rule in RULES:
            for c in rule(a):
                key = (c.get("asset_id"), c["title"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(c)
    out.sort(key=lambda c: c["evidence"]["priority"], reverse=True)
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_map_rules tests.test_core -v`
Expected: PASS — all OK.

- [ ] **Step 5: Commit**

```bash
git add modules/map_ptt/rules.py tests/test_map_rules.py
git commit -m "feat(map_ptt): deterministic asset->candidate-finding rules"
```

---

### Task 6: `map_ptt` module (orchestration + manifest)

**Files:**
- Create: `modules/map_ptt/module.json`
- Create: `modules/map_ptt/module.py`
- Test: `tests/test_map_ptt.py`

**Interfaces:**
- Consumes: `rules.map_assets` (Task 5, loaded by path); `ctx.store.list_assets` (Task 1); `ctx.reason` (Task 4); `atpt.module.Module` / `ModuleResult`.
- Produces: `MapPTT(Module)` with `run(ctx) -> ModuleResult` (findings = candidate dicts). Discovered as module id `map_ptt`.

- [ ] **Step 1: Write the manifest**

Create `modules/map_ptt/module.json`:
```json
{
  "id": "map_ptt",
  "name": "PTT Attack-Surface Router",
  "phase": "map",
  "entrypoint": "module:MapPTT",
  "consumes": ["asset"],
  "provides": ["finding"],
  "intrusive": false,
  "run_modes": ["step", "semi", "full"],
  "enabled": true,
  "extracted_from": "GreyDGL/PentestGPT@e8b1bb7",
  "description": "Decomposes assets into prioritized candidate findings (PTT); deterministic rules + optional reasoning-ladder enrichment."
}
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_map_ptt.py`:
```python
import tempfile
import unittest
from pathlib import Path

from atpt.engine import Orchestrator
from atpt.module import Manifest, Module, ModuleResult, RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore


class _FakeExploit(Module):
    def __init__(self):
        super().__init__(Manifest(id="z_exploit", name="Z", phase="exploit",
                                  entrypoint="x", consumes=["finding"], intrusive=False),
                         Path("."))

    def run(self, ctx):
        return ModuleResult(summary="z ran")


class MapPTTTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {"in_scope_domains": ["x.com"]},
                                     "s.json", "full", {})
        self.store.upsert_asset("E", {"asset_type": "service", "value": "h:6379",
                                      "service": "redis"})
        self.eng = self.store.get_engagement("E")
        mods = discover(Path("modules"), Path("."))
        self.assertIn("map_ptt", mods)                      # registry finds it
        self.map = mods["map_ptt"]

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, reasoner=None, dry_run=False):
        return RunContext(engagement=self.eng, scope={}, store=self.store,
                          project_dir=Path("."), dry_run=dry_run, reasoner=reasoner)

    def test_run_produces_candidate_findings(self):
        res = self.map.run(self._ctx())
        self.assertTrue(res.findings)
        self.assertEqual(res.findings[0]["status"], "candidate")

    def test_dry_run_mutates_nothing(self):
        res = self.map.run(self._ctx(dry_run=True))
        self.assertEqual(res.findings, [])
        self.assertTrue(res.planned)

    def test_enrich_degrades_when_reasoner_errors(self):
        class _Boom:
            def reason(self, p, phase): raise RuntimeError("no provider")
        # config asks for enrich; reasoner blows up -> rules-only, no crash
        self.store.create_engagement("E", "E", {}, "s.json", "full",
                                     {"map": {"enrich": True}})
        self.eng = self.store.get_engagement("E")
        self.store.upsert_asset("E", {"asset_type": "service", "value": "h:6379",
                                      "service": "redis"})
        res = self.map.run(self._ctx(reasoner=_Boom()))
        self.assertTrue(res.findings)                       # rules still stand

    def test_map_flips_finding_token_for_downstream(self):
        orch = Orchestrator(self.store, {"map_ptt": self.map,
                                         "z_exploit": _FakeExploit()}, Path("."))
        res = orch.run(self.eng, "full")
        self.assertIn("map_ptt", res["executed"])
        self.assertIn("z_exploit", res["executed"])         # unlocked by finding token
        self.assertGreater(self.store.count_findings("E"), 0)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m unittest tests.test_map_ptt -v`
Expected: FAIL — `map_ptt` not in discovered modules (module.py missing) / import error.

- [ ] **Step 4: Write the module**

Create `modules/map_ptt/module.py`:
```python
"""Map/PTT router — extraction of PentestGPT's task-decomposition concept.
Turns the asset inventory into prioritized CANDIDATE findings via deterministic
rules (rules.py), with optional reasoning-ladder enrichment (ctx.reason).
Non-intrusive: reasons over recon output, touches no target."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path

from atpt.module import Module, ModuleResult

# Load the sibling rules.py by path (the module dir is not on sys.path).
_spec = importlib.util.spec_from_file_location(
    "map_ptt_rules", Path(__file__).with_name("rules.py"))
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)

ENRICH_PROMPT = (
    "You are a penetration-testing triage assistant. Given JSON of discovered "
    "assets and current candidate findings, return ONLY a JSON list of ADDITIONAL "
    "candidate findings as objects with keys: title, domain, severity "
    "(low|medium|high|critical), owasp, cvss (number), asset_id. Return [] if you "
    "have nothing to add.\n\n"
)


class MapPTT(Module):
    def run(self, ctx) -> ModuleResult:
        eid = ctx.engagement["id"]
        assets = ctx.store.list_assets(eid)
        cands = rules.map_assets(assets)

        if ctx.dry_run:
            ctx.emit("dry_run",
                     f"[map] would derive {len(cands)} candidate findings from "
                     f"{len(assets)} assets", phase="map", module=self.id)
            return ModuleResult(
                planned=[f"map {len(assets)} assets -> {len(cands)} candidates"],
                summary=f"dry-run: {len(cands)} candidate findings planned")

        cfg = json.loads(ctx.engagement.get("config") or "{}")
        if cfg.get("map", {}).get("enrich", True):
            cands = self._enrich(ctx, assets, cands)

        ctx.emit("map_done",
                 f"[map] {len(cands)} candidate findings from {len(assets)} assets",
                 phase="map", module=self.id,
                 data={"assets": len(assets), "candidates": len(cands)})
        return ModuleResult(findings=cands,
                            summary=f"{len(cands)} candidate findings from "
                                    f"{len(assets)} assets")

    def _enrich(self, ctx, assets, cands):
        try:
            summary = [{"asset_id": a.get("id"), "value": a.get("value"),
                        "type": a.get("asset_type"), "service": a.get("service"),
                        "tech": a.get("tech"), "http_status": a.get("http_status")}
                       for a in assets]
            prompt = ENRICH_PROMPT + json.dumps(
                {"assets": summary,
                 "candidates": [{"asset_id": c["asset_id"], "title": c["title"]}
                                for c in cands]})
            text = ctx.reason(prompt, phase="map")
            if not text:
                return cands
            extra = json.loads(text[text.index("["): text.rindex("]") + 1])
            seen = {(c["asset_id"], c["title"]) for c in cands}
            for e in extra:
                key = (e.get("asset_id"), e.get("title"))
                if not e.get("title") or key in seen:
                    continue
                seen.add(key)
                cands.append({"asset_id": e.get("asset_id"), "title": e["title"],
                              "domain": e.get("domain", "Web"),
                              "severity": e.get("severity", "low"),
                              "owasp": e.get("owasp"), "cvss": e.get("cvss"),
                              "status": "candidate", "source_tool": "map_ptt",
                              "evidence": {"rule": "llm_enrich",
                                           "provenance": "reasoning"}})
        except Exception as exc:
            ctx.emit("map_enrich_skipped", f"[map] enrichment skipped: {exc}",
                     "warn", phase="map", module=self.id)
        return cands
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_map_ptt tests.test_core -v`
Expected: PASS — all OK. Confirm `map_ptt` executes then `z_exploit` unlocks.

- [ ] **Step 6: Verify the module is discovered by the CLI**

Run: `python3 -m atpt modules`
Expected: a row `map_ptt   map   False   GreyDGL/PentestGPT@e8b1bb7`.

- [ ] **Step 7: Commit**

```bash
git add modules/map_ptt/module.json modules/map_ptt/module.py tests/test_map_ptt.py
git commit -m "feat(map_ptt): PTT router module producing candidate findings"
```

---

### Task 7: Document the map phase + reasoning layer

**Files:**
- Modify: `docs/CORE.md` (add a short "Reasoning layer" subsection after "Run modes")

**Interfaces:** none (docs only).

- [ ] **Step 1: Add the docs section**

In `docs/CORE.md`, after the "Run modes" table and dry-run paragraph, insert:
```markdown
## Reasoning layer (`atpt/reasoning.py`)
Modules that reason (not just wrap a CLI) call `ctx.reason(prompt, phase)`. It runs
a **provider ladder** from the engagement `config.reasoning`: registered providers
(`cli` / `http_api` / `ollama`), tried in `preference` order, filtered by a per-phase
`policy` (`any` / `hosted_ok` / `local_only`). On a **refusal or error** it advances
to the next provider — ultimately a local model — never rewriting the prompt to defeat
a model's guardrails. Exhaustion returns `None`, so a module falls back to deterministic
logic. API keys are read from env vars (`key_env`) at call time; never stored.

The `map_ptt` module is the first consumer: it maps assets to prioritized **candidate
findings** with deterministic rules, then optionally enriches via `ctx.reason`.
```

- [ ] **Step 2: Run the full suite one last time**

Run: `python3 -m unittest discover -s tests -v`
Expected: all tests across all files PASS.

- [ ] **Step 3: Commit**

```bash
git add docs/CORE.md
git commit -m "docs(core): document reasoning layer and map phase"
```

---

## Self-Review

**Spec coverage:**
- §5 `map_ptt` module → Tasks 5, 6. ✅
- §6 reasoning ladder (registry, resolution, backends, refusal, secrets) → Tasks 2, 3. ✅
- §7 config schema → exercised in Tasks 3 (env key), 6 (`map.enrich`), and ladder tests. ✅
- §8 core additions (`list_assets`, `reasoning.py`, `RunContext.reason`) → Tasks 1, 2/3, 4. ✅
- §9 finding shape → Task 5 `_cand`. ✅
- §10 pipeline effect (flip `finding` token) → Task 6 `test_map_flips_finding_token_for_downstream`. ✅
- §11 testing plan → covered across Tasks 1-6. ✅
- §13 boundary statement → encoded in reasoning docstring + Task 7 docs + no-bypass tests. ✅

**Placeholder scan:** none — every code step contains full implementation and full test bodies.

**Type consistency:** `map_assets` signature, candidate dict keys (`asset_id/title/domain/owasp/severity/cvss/status/source_tool/evidence`), `ReasoningLadder(config, emit)`, `reason(prompt, phase) -> ReasoningResult | None`, `ctx.reason(prompt, phase) -> str | None`, and `BACKENDS` name→fn shape are consistent across Tasks 2-6.

**YAGNI note:** no PTT tree table, no async, no credential UI — deferred per spec §3.
