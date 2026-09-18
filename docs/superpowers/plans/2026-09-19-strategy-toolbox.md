# Strategy Toolbox (Learned Skills) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the offensive agent memory — distill a *successful* trajectory into a reusable, hand-editable **skill**, and on later targets retrieve matching skills and inject them into the executor prompt, with safety unchanged (every suggested command is still vetted by `ScopeGuard`).

**Architecture:** A self-contained toolbox subsystem. JSON files under `<project_dir>/toolbox/` are the source of truth (hand-editable, shareable); a rebuildable SQLite index (`toolbox/index.db`) accelerates tag retrieval. `atpt/toolbox.py` (stdlib-only, cross-engagement) owns files + index. `modules/agent_offensive/distill.py` turns a winning transcript into a templated skill via one `ctx.reason` call. `loop.py` searches the toolbox at run start (and as services are discovered), injects a compact "LEARNED PLAYBOOK" block, and on a run that produced findings distills + saves a new skill. A minimal web panel makes skills operator-visible. Skills only *suggest*; they can never widen scope or the allow-list.

**Tech Stack:** Python 3 stdlib only for `atpt/` (`json`, `sqlite3`, `pathlib`, `re`, `time`, `ipaddress`). Tests: `unittest` (also runnable under pytest). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-18-llm-driven-offensive-agent-design.md` (Phase 2 — Strategy Toolbox, lines 233-262). Refinements settled during brainstorming: storage = **files + SQLite index** (user choice); success = **the run produced ≥1 finding**; reuse = **placeholders the executor fills** (not a rigid replay engine); plus a minimal operator-visible web panel.

## Global Constraints

- `atpt/toolbox.py` MUST be **stdlib-only** (matches `atpt/scope.py`, `atpt/toolwrap.py`). Modules may import from `atpt`.
- Every file starts with `from __future__ import annotations` and a terse module docstring, matching the codebase style.
- **Safety is unchanged and non-negotiable:** a skill only injects *text* into the prompt. Every command the agent runs still passes `ScopeGuard.vet(...)` / `session_scope_ok(...)`. Distillation writes **only** under `<project_dir>/toolbox/` (no egress).
- **Backward compatibility:** `run_loop(...)` gains only keyword-only params with defaults (`toolbox=None`, `distill_fn=None`). With them unset the loop behaves exactly as today; all existing `tests/test_agent_loop.py` cases must still pass unchanged.
- Injected playbook text is deliberately **small** (top-2 skills, ≤4 steps each) — transcript bloat is what caused the Opus timeouts noted in the project history.
- Tests use a **fake reasoner** (scripted strings) and a **tmp toolbox dir**; no network, no real LLM, no real scanning.
- **Test commands (this environment):** focused runs use `python3 -m unittest tests.test_<name> -v`; the **full suite runs under pytest**: `python3 -m pytest -q tests/` (the `unittest discover` runner collides with the `atpt` CLI argparse during collection and prints CLI help instead of running tests — do not use it). Baseline before this work: **281 passed**, plus 1 pre-existing `sqlite3.OperationalError: readonly database` ResourceWarning from a threaded web/desktop test (unrelated to the toolbox — not introduced by these tasks). The suite must stay green; your tasks must add no new warnings.

---

### Task 0: Commit the in-flight prompt refinements

The working tree already has uncommitted, coherent changes (executor-prompt clarification about raw-argv/no-shell + command-injection technique, and a matching scope-wall test). Commit them first so the toolbox work starts from a clean tree. **Do not modify them.**

- [ ] **Step 1: Confirm the suite is green with the WIP in place**

Run: `python3 -m pytest -q tests/`
Expected: all pass.

- [ ] **Step 2: Commit the WIP**

```bash
git add modules/agent_offensive/loop.py tests/test_agent_guard.py
git commit -m "feat(agent): clarify raw-argv/no-shell + command-injection prompt; wall test for revshell payload"
```

---

### Task 1: Toolbox store — files + index (save / list / get / delete / reindex)

**Files:**
- Create: `atpt/toolbox.py`
- Test: `tests/test_toolbox.py`

**Interfaces:**
- Produces:
  - `slugify(name: str) -> str`
  - `class Toolbox`
    - `Toolbox(root: str | Path)` — creates `root`; index opened lazily.
    - `save(skill: dict) -> Path | None` — writes `<root>/<slug>.json` and indexes it; returns the path, or `None` if the skill has no name or no usable steps.
    - `list_skills() -> list[dict]` — reads the JSON files (no index).
    - `get(name: str) -> dict | None`
    - `delete(name: str) -> bool`
    - `reindex() -> int` — rebuilds the index from the files dir; returns count.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_toolbox.py
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from atpt.toolbox import Toolbox, slugify


class ToolboxStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name) / "toolbox"
        self.tb = Toolbox(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _skill(self, name="SQLi UNION dump", svc=("http", "mysql")):
        return {"name": name,
                "applies_to": {"goal_tags": ["dump", "db"], "service_tags": list(svc)},
                "steps": [{"command": ["sqlmap", "-u", "{TARGET_URL}", "--batch", "--dump"],
                           "note": "id param"}],
                "success_note": "UNION SQLi dumped users"}

    def test_slugify(self):
        self.assertEqual(slugify("SQLi UNION dump"), "sqli-union-dump")
        self.assertEqual(slugify("  weird__Name!! "), "weird-name")
        self.assertEqual(slugify(""), "skill")

    def test_save_writes_file_and_returns_path(self):
        p = self.tb.save(self._skill())
        self.assertTrue(p.exists())
        self.assertEqual(p.name, "sqli-union-dump.json")
        rec = json.loads(p.read_text())
        self.assertEqual(rec["applies_to"]["service_tags"], ["http", "mysql"])
        self.assertIn("updated_at", rec)

    def test_save_rejects_nameless_or_stepless(self):
        self.assertIsNone(self.tb.save({"name": "", "steps": [{"command": ["x"]}]}))
        self.assertIsNone(self.tb.save({"name": "x", "steps": []}))

    def test_list_and_get(self):
        self.tb.save(self._skill())
        self.assertEqual(len(self.tb.list_skills()), 1)
        self.assertEqual(self.tb.get("SQLi UNION dump")["success_note"], "UNION SQLi dumped users")
        self.assertIsNone(self.tb.get("nope"))

    def test_delete_removes_file(self):
        self.tb.save(self._skill())
        self.assertTrue(self.tb.delete("SQLi UNION dump"))
        self.assertFalse(self.tb.delete("SQLi UNION dump"))
        self.assertEqual(self.tb.list_skills(), [])

    def test_reindex_picks_up_hand_dropped_file(self):
        # a shared skill dropped in by hand (not via save())
        (self.root).mkdir(parents=True, exist_ok=True)
        (self.root / "lfi-etc-passwd.json").write_text(json.dumps({
            "name": "lfi-etc-passwd",
            "applies_to": {"goal_tags": ["lfi"], "service_tags": ["http"]},
            "steps": [{"command": ["curl", "{TARGET_URL}/?p=../../etc/passwd"], "note": ""}],
            "success_note": "LFI"}))
        self.assertEqual(self.tb.reindex(), 1)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_toolbox -v`
Expected: FAIL (`No module named 'atpt.toolbox'`).

- [ ] **Step 3: Implement the store half of `atpt/toolbox.py`**

```python
"""Strategy Toolbox: learned skills persisted as hand-editable JSON files (the
source of truth) plus a rebuildable SQLite index for fast tag retrieval. A skill
is a distilled SUCCESSFUL trajectory; it only ever SUGGESTS commands — every
command it yields is still vetted by ScopeGuard at execution time, so a skill can
never widen scope or the allow-list. Stdlib-only, cross-engagement, portable:
copy the toolbox/ dir elsewhere and reindex() rebuilds the index."""
from __future__ import annotations
import json
import re
import sqlite3
import time
from pathlib import Path

_SLUG = re.compile(r"[^a-z0-9]+")
_INDEX = "index.db"


def slugify(name: str) -> str:
    s = _SLUG.sub("-", (name or "").strip().lower()).strip("-")
    return s or "skill"


def _norm_tags(v) -> list[str]:
    if isinstance(v, str):
        v = [v]
    return sorted({str(x).strip().lower() for x in (v or []) if str(x).strip()})


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Toolbox:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._cx = None

    # --- files (source of truth) --------------------------------------------
    def path_for(self, name: str) -> Path:
        return self.root / f"{slugify(name)}.json"

    def list_skills(self) -> list[dict]:
        out = []
        for p in sorted(self.root.glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except Exception:
                continue
        return out

    def get(self, name: str):
        p = self.path_for(name)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text())
        except Exception:
            return None

    def save(self, skill: dict):
        name = str(skill.get("name") or "").strip()
        raw_steps = skill.get("steps") or []
        steps = [{"command": [str(x) for x in (s.get("command") or [])],
                  "note": str(s.get("note") or "")}
                 for s in raw_steps if s.get("command")]
        if not name or not steps:
            return None
        rec = {
            "name": name,
            "applies_to": {
                "goal_tags": _norm_tags((skill.get("applies_to") or {}).get("goal_tags")),
                "service_tags": _norm_tags((skill.get("applies_to") or {}).get("service_tags")),
            },
            "steps": steps,
            "provenance": skill.get("provenance") or {},
            "success_note": str(skill.get("success_note") or ""),
            "updated_at": skill.get("updated_at") or _now(),
        }
        p = self.path_for(name)
        p.write_text(json.dumps(rec, indent=2, ensure_ascii=False))
        self._index_one(rec, p)
        return p

    def delete(self, name: str) -> bool:
        p = self.path_for(name)
        existed = p.exists()
        if existed:
            p.unlink()
        db = self._db()
        db.execute("DELETE FROM skills WHERE name=?", (slugify(name),))
        db.commit()
        return existed

    # --- index (rebuildable accelerator) ------------------------------------
    def _db(self):
        if self._cx is None:
            self._cx = sqlite3.connect(str(self.root / _INDEX))
            self._cx.execute(
                "CREATE TABLE IF NOT EXISTS skills (name TEXT PRIMARY KEY, path TEXT, "
                "goal_tags TEXT, service_tags TEXT, success_note TEXT, updated_at TEXT)")
            self._cx.commit()
        return self._cx

    def _index_one(self, rec: dict, p: Path):
        db = self._db()
        db.execute(
            "INSERT INTO skills (name,path,goal_tags,service_tags,success_note,updated_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET path=excluded.path, "
            "goal_tags=excluded.goal_tags, service_tags=excluded.service_tags, "
            "success_note=excluded.success_note, updated_at=excluded.updated_at",
            (slugify(rec["name"]), str(p),
             " ".join(rec["applies_to"]["goal_tags"]),
             " ".join(rec["applies_to"]["service_tags"]),
             rec.get("success_note", ""), rec.get("updated_at", "")))
        db.commit()

    def reindex(self) -> int:
        db = self._db()
        db.execute("DELETE FROM skills")
        db.commit()
        n = 0
        for p in sorted(self.root.glob("*.json")):
            try:
                rec = json.loads(p.read_text())
            except Exception:
                continue
            ap = rec.get("applies_to") or {}
            rec["applies_to"] = {"goal_tags": _norm_tags(ap.get("goal_tags")),
                                 "service_tags": _norm_tags(ap.get("service_tags"))}
            rec.setdefault("success_note", "")
            rec.setdefault("updated_at", "")
            self._index_one(rec, p)
            n += 1
        return n
```

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest tests.test_toolbox -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add atpt/toolbox.py tests/test_toolbox.py
git commit -m "feat(toolbox): learned-skill store — JSON files + rebuildable SQLite index"
```

---

### Task 2: Toolbox retrieval — tag ranking + tag derivation helpers

**Files:**
- Modify: `atpt/toolbox.py`
- Test: `tests/test_toolbox.py` (add a class)

**Interfaces:**
- Consumes: `Toolbox` from Task 1.
- Produces:
  - `goal_tags(goal: str) -> list[str]` — keyword tags from free-text goal (lowercased words ≥3 chars, stopwords + generic CTF words dropped).
  - `service_tags_from_assets(assets: list[dict]) -> list[str]` — service tags from discovered assets (`service` values; `http` for web assets; first token of `product`/`tech`).
  - `Toolbox.search(goal_tags_q, service_tags_q, limit=2) -> list[dict]` — ranks indexed skills by `2*service_overlap + goal_overlap`, ties broken by recency; returns full skill dicts.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_toolbox.py
from atpt.toolbox import goal_tags, service_tags_from_assets


class ToolboxRetrievalTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tb = Toolbox(Path(self._tmp.name) / "toolbox")

    def tearDown(self):
        self._tmp.cleanup()

    def test_goal_tags_drops_generic_and_short(self):
        self.assertEqual(goal_tags("Capture the flags on the box"), [])
        tags = goal_tags("Exploit the Wordpress login")
        self.assertIn("wordpress", tags)
        self.assertIn("login", tags)
        self.assertNotIn("the", tags)

    def test_service_tags_from_assets(self):
        assets = [{"asset_type": "service", "service": "ssh"},
                  {"asset_type": "service", "service": "http", "product": "Apache httpd"},
                  {"asset_type": "web_endpoint", "url": "http://h/"}]
        tags = service_tags_from_assets(assets)
        self.assertIn("ssh", tags)
        self.assertIn("http", tags)
        self.assertIn("apache", tags)

    def test_search_ranks_service_overlap_highest(self):
        self.tb.save({"name": "http-sqli", "applies_to": {"goal_tags": [],
                     "service_tags": ["http", "mysql"]},
                     "steps": [{"command": ["sqlmap", "-u", "{TARGET_URL}"]}], "success_note": "a"})
        self.tb.save({"name": "ssh-brute", "applies_to": {"goal_tags": ["login"],
                     "service_tags": ["ssh"]},
                     "steps": [{"command": ["hydra", "{TARGET}"]}], "success_note": "b"})
        hits = self.tb.search(goal_tags_q=["login"], service_tags_q=["http", "mysql"], limit=2)
        self.assertEqual(hits[0]["name"], "http-sqli")   # 2*2 > 1 (goal 'login')

    def test_search_returns_nothing_on_no_overlap(self):
        self.tb.save({"name": "ssh-brute", "applies_to": {"service_tags": ["ssh"]},
                      "steps": [{"command": ["hydra", "{TARGET}"]}]})
        self.assertEqual(self.tb.search([], ["smb"]), [])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_toolbox -v`
Expected: FAIL (`cannot import name 'goal_tags'`).

- [ ] **Step 3: Implement the retrieval half in `atpt/toolbox.py`**

Add the module-level constants near the top (after `_SLUG`):

```python
_WORD = re.compile(r"[a-z0-9]{3,}")
_STOP = frozenset({"the", "and", "for", "with", "from", "into", "that", "this",
                   "your", "are", "was", "will", "can", "all", "any", "use", "via",
                   "get", "got", "run", "flag", "flags", "capture", "target",
                   "host", "box", "machine", "read", "both", "user", "root"})
```

Add module-level functions:

```python
def goal_tags(goal: str) -> list[str]:
    return sorted({w for w in _WORD.findall((goal or "").lower()) if w not in _STOP})


def service_tags_from_assets(assets) -> list[str]:
    tags = set()
    for a in assets or []:
        v = a.get("service")
        if v:
            tags.add(str(v).strip().lower())
        if a.get("asset_type") in ("web_endpoint", "web_path"):
            tags.add("http")
        for k in ("product", "tech"):
            pv = a.get(k)
            if isinstance(pv, str) and pv.strip():
                tags.add(pv.strip().lower().split()[0].split("/")[0])
    return sorted(tags)
```

Add the method on `Toolbox`:

```python
    def search(self, goal_tags_q, service_tags_q, limit=2) -> list[dict]:
        gt = set(_norm_tags(goal_tags_q))
        st = set(_norm_tags(service_tags_q))
        scored = []
        for r in self._db().execute("SELECT name,goal_tags,service_tags,updated_at FROM skills"):
            sg = set((r[1] or "").split())
            ss = set((r[2] or "").split())
            score = 2 * len(st & ss) + len(gt & sg)
            if score > 0:
                scored.append((score, r[3] or "", r[0]))
        scored.sort(reverse=True)
        out = []
        for _, _, slug in scored[:limit]:
            p = self.root / f"{slug}.json"
            if p.exists():
                try:
                    out.append(json.loads(p.read_text()))
                except Exception:
                    continue
        return out
```

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest tests.test_toolbox -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add atpt/toolbox.py tests/test_toolbox.py
git commit -m "feat(toolbox): tag-overlap retrieval (service-weighted) + goal/service tag derivation"
```

---

### Task 3: Distillation — turn a winning transcript into a templated skill

**Files:**
- Modify: `modules/agent_offensive/actions.py` (extract a reusable `last_json`)
- Create: `modules/agent_offensive/distill.py`
- Test: `tests/test_agent_distill.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `actions.last_json(text: str) -> dict | None` (and `parse_action` refactored to use it — behavior unchanged).
  - `distill.distill(*, goal, transcript, reason_fn, substitutions=None, provenance=None) -> dict | None` — one `reason_fn` call → a skill dict with target-specific tokens replaced by placeholders; `None` on empty/junk.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_agent_distill.py
import unittest

from modules.agent_offensive.distill import distill
from modules.agent_offensive.actions import last_json


class LastJsonTest(unittest.TestCase):
    def test_returns_last_object(self):
        self.assertEqual(last_json('noise {"a":1} tail {"b":2} end'), {"b": 2})

    def test_none_on_junk(self):
        self.assertIsNone(last_json("no json here"))
        self.assertIsNone(last_json(""))


class DistillTest(unittest.TestCase):
    def test_templatises_concrete_target_and_listener(self):
        model = ('Here is the skill:\n'
                 '{"name":"sqli-dump","applies_to":{"goal_tags":["dump"],'
                 '"service_tags":["http","mysql"]},'
                 '"steps":[{"command":["sqlmap","-u","http://10.1.1.5/item?id=1","--dump"],'
                 '"note":"id"}],"success_note":"UNION SQLi"}')
        skill = distill(goal="dump the db", transcript="...winning steps...",
                        reason_fn=lambda p: model,
                        substitutions={"10.1.1.5": "{TARGET}"},
                        provenance={"engagement": "e1"})
        self.assertEqual(skill["steps"][0]["command"][2], "http://{TARGET}/item?id=1")
        self.assertEqual(skill["provenance"]["engagement"], "e1")
        self.assertEqual(skill["applies_to"]["service_tags"], ["http", "mysql"])

    def test_none_when_model_returns_no_steps(self):
        self.assertIsNone(distill(goal="x", transcript="y",
                                  reason_fn=lambda p: '{"name":"z"}'))
        self.assertIsNone(distill(goal="x", transcript="y", reason_fn=lambda p: "junk"))

    def test_prompt_receives_goal_and_transcript(self):
        seen = {}

        def rf(p):
            seen["p"] = p
            return '{"name":"n","steps":[{"command":["id"]}]}'

        distill(goal="GOALTEXT", transcript="TRANSCRIPTTEXT", reason_fn=rf)
        self.assertIn("GOALTEXT", seen["p"])
        self.assertIn("TRANSCRIPTTEXT", seen["p"])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_agent_distill -v`
Expected: FAIL (`No module named 'modules.agent_offensive.distill'`).

- [ ] **Step 3: Add `last_json` to `actions.py` and refactor `parse_action`**

In `modules/agent_offensive/actions.py`, add after `_iter_json_objects`:

```python
def last_json(text: str):
    """The last complete top-level JSON object in the text, or None."""
    obj = None
    for chunk in _iter_json_objects(text or ""):
        try:
            obj = json.loads(chunk)
        except Exception:
            continue
    return obj if isinstance(obj, dict) else None
```

Replace the head of `parse_action` (the manual scan) with a call to it:

```python
def parse_action(text: str) -> "Action | None":
    obj = last_json(text)
    if obj is None:
        return None
    rationale = str(obj.get("rationale") or "")
    # ... rest unchanged ...
```

- [ ] **Step 4: Create `modules/agent_offensive/distill.py`**

```python
"""Distill a SUCCESSFUL trajectory into a reusable skill. One reasoning call
summarises the winning steps into a skill JSON; then we deterministically replace
target-specific values (the concrete target host/URL, listener host:port) with
placeholders so the skill applies to a new box. Best-effort — returns None if the
model yields nothing usable. Safety is unchanged: a saved skill only SUGGESTS
commands, each still vetted by ScopeGuard when reused."""
from __future__ import annotations
import time

from .actions import last_json

_PROMPT = (
    "You are distilling a SUCCESSFUL penetration-testing session into a reusable "
    "skill for FUTURE targets. The goal was: {goal}\n\n"
    "From the transcript below, extract the MINIMAL ordered sequence of commands "
    "that actually led to success. Omit failed detours and dead ends. Reply with "
    "ONE JSON object and nothing else:\n"
    '{{"name":"short-kebab-name",'
    '"applies_to":{{"goal_tags":["keyword",...],"service_tags":["http","ssh",...]}},'
    '"steps":[{{"command":["bin","arg",...],"note":"why this step"}}],'
    '"success_note":"one line describing what worked"}}\n'
    "Set service_tags to the services the target actually exposed. Keep commands "
    "generic where you can. Use the argv array form for every command.\n\n"
    "Transcript:\n{transcript}\n")


def _templatise(tok: str, subs: dict) -> str:
    for concrete, placeholder in (subs or {}).items():
        if concrete:
            tok = tok.replace(concrete, placeholder)
    return tok


def distill(*, goal, transcript, reason_fn, substitutions=None, provenance=None):
    text = reason_fn(_PROMPT.format(goal=goal, transcript=transcript))
    obj = last_json(text or "")
    if not isinstance(obj, dict) or not obj.get("steps"):
        return None
    for step in obj["steps"]:
        cmd = step.get("command")
        if isinstance(cmd, list):
            step["command"] = [_templatise(str(tok), substitutions) for tok in cmd]
    obj["provenance"] = provenance or {}
    obj.setdefault("success_note", "")
    obj["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return obj
```

- [ ] **Step 5: Run tests (distill + existing actions/loop regression)**

Run: `python3 -m unittest tests.test_agent_distill tests.test_agent_actions tests.test_agent_loop -v`
Expected: PASS (distill green; the `parse_action` refactor keeps actions/loop green).

- [ ] **Step 6: Commit**

```bash
git add modules/agent_offensive/actions.py modules/agent_offensive/distill.py tests/test_agent_distill.py
git commit -m "feat(agent): distill a winning transcript into a templated skill (+ shared last_json)"
```

---

### Task 4: Loop — retrieve + inject a compact LEARNED PLAYBOOK

**Files:**
- Modify: `modules/agent_offensive/loop.py`
- Test: `tests/test_agent_loop.py` (add cases)

**Interfaces:**
- Consumes: `Toolbox.search`, `goal_tags`, `service_tags_from_assets` from `atpt.toolbox`.
- Produces: `run_loop(..., toolbox=None, distill_fn=None)` — new keyword-only params (Task 5 uses `distill_fn`). When `toolbox` is set, a `LEARNED PLAYBOOK` block is injected into each step's prompt; refreshed when discovered service tags change. Return signature unchanged: `(assets, findings, summary)`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_agent_loop.py
from tempfile import TemporaryDirectory
from pathlib import Path
from atpt.toolbox import Toolbox


class LoopToolboxInjectTest(unittest.TestCase):
    def test_playbook_hint_injected_after_service_discovered(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tb = Toolbox(Path(tmp.name) / "toolbox")
        tb.save({"name": "ssh-cred-reuse", "applies_to": {"service_tags": ["ssh"]},
                 "steps": [{"command": ["hydra", "-l", "root", "{TARGET}"]}],
                 "success_note": "reused creds over ssh"})
        prompts = []
        # step 1 runs a real command (so an ssh asset is harvested); step 2's
        # prompt should then carry the ssh skill. A 'done' first action would end
        # the loop before any harvest, so the hint must be checked on prompt[1].
        scripted = iter(['{"command":["nmap","-Pn","10.1.1.5"]}', '{"done": true}'])

        def rf(p):
            prompts.append(p)
            return next(scripted)

        run_loop(goal="get a shell", guard=guard(), scope=SCOPE, reason_fn=rf,
                 max_steps=2, emit=lambda *a, **k: None,
                 execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=lambda a, r: ([{"asset_type": "service", "service": "ssh",
                                            "value": "10.1.1.5:22/ssh"}], []),
                 toolbox=tb)
        self.assertNotIn("LEARNED PLAYBOOK", prompts[0])   # no services discovered yet
        self.assertIn("LEARNED PLAYBOOK", prompts[1])
        self.assertIn("ssh-cred-reuse", prompts[1])

    def test_toolbox_none_leaves_prompt_clean(self):
        prompts = []

        def rf(p):
            prompts.append(p)
            return '{"done": true}'

        run_loop(goal="x", guard=guard(), reason_fn=rf, max_steps=1,
                 emit=lambda *a, **k: None,
                 execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=lambda a, r: ([], []))
        self.assertFalse(any("LEARNED PLAYBOOK" in p for p in prompts))
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_agent_loop -v`
Expected: FAIL (`run_loop() got an unexpected keyword argument 'toolbox'`).

- [ ] **Step 3: Implement injection in `loop.py`**

Add imports near the top:

```python
from atpt.toolbox import goal_tags as _goal_tags, service_tags_from_assets as _service_tags
```

Add a `{playbook}` field to `_PROMPT` immediately before the transcript line — change the final segment from:

```python
    "Transcript so far:\n{transcript}\n")
```
to:
```python
    "{playbook}Transcript so far:\n{transcript}\n")
```

Add a helper above `run_loop`:

```python
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
```

Change the `run_loop` signature to add the two keyword-only params:

```python
def run_loop(*, goal, guard, reason_fn, max_steps, emit, execute_fn, harvest_fn,
             scope=None, halt_fn=lambda: False, toolbox=None, distill_fn=None):
```

At the top of `run_loop`, after `assets, findings, transcript = [], [], []`, initialise the playbook (goal-only match to start):

```python
    playbook, _svc_sig = "", None
    if toolbox is not None:
        try:
            playbook = _build_playbook(toolbox.search(_goal_tags(goal), []))
        except Exception:
            playbook = ""
```

Inside the `for step` loop, refresh the playbook when discovered services change, then thread it into the `.format(...)`. Replace the existing reason call:

```python
        text = reason_fn(_PROMPT.format(goal=goal, transcript="\n".join(transcript[-24:])))
```
with:
```python
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
```

- [ ] **Step 4: Run to verify they pass (and the whole loop suite is green)**

Run: `python3 -m unittest tests.test_agent_loop -v`
Expected: PASS (new cases green; all pre-existing cases still pass — `toolbox` defaults to `None`).

- [ ] **Step 5: Commit**

```bash
git add modules/agent_offensive/loop.py tests/test_agent_loop.py
git commit -m "feat(agent): inject a compact LEARNED PLAYBOOK from the toolbox into the loop"
```

---

### Task 5: Loop — distill + save a skill when the run produced findings

**Files:**
- Modify: `modules/agent_offensive/loop.py`
- Test: `tests/test_agent_loop.py` (add cases)

**Interfaces:**
- Consumes: `distill_fn` (injected in Task 4's signature), `toolbox.save`.
- Produces: on any run end where `findings` is non-empty, the loop calls `distill_fn(goal, transcript_text)` and `toolbox.save(skill)`, emitting `agent_skill_saved`. All existing return points funnel through one `_finish(summary)`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_agent_loop.py
class LoopToolboxSaveTest(unittest.TestCase):
    def test_saves_skill_on_success(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tb = Toolbox(Path(tmp.name) / "toolbox")
        scripted = iter([
            '{"command":["curl","http://10.1.1.5/"]}',   # produces a flag finding via harvest
            '{"done": true}',
        ])

        def hv(argv, res):
            return ([], [{"title": "Flag captured: flag{x}", "severity": "critical",
                          "status": "validated", "evidence": {"flag": "flag{x}"}}])

        skill = {"name": "curl-flag", "applies_to": {"service_tags": ["http"]},
                 "steps": [{"command": ["curl", "http://{TARGET}/"]}],
                 "success_note": "flag on /"}

        run_loop(goal="capture the flag", guard=guard(), scope=SCOPE,
                 reason_fn=lambda p: next(scripted), max_steps=4,
                 emit=lambda *a, **k: None,
                 execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=hv, toolbox=tb, distill_fn=lambda g, t: skill)
        self.assertEqual([s["name"] for s in tb.list_skills()], ["curl-flag"])

    def test_no_save_without_findings(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tb = Toolbox(Path(tmp.name) / "toolbox")
        called = {"n": 0}

        def df(g, t):
            called["n"] += 1
            return {"name": "x", "steps": [{"command": ["id"]}]}

        run_loop(goal="x", guard=guard(), scope=SCOPE,
                 reason_fn=lambda p: '{"done": true}', max_steps=2,
                 emit=lambda *a, **k: None,
                 execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=lambda a, r: ([], []), toolbox=tb, distill_fn=df)
        self.assertEqual(called["n"], 0)
        self.assertEqual(tb.list_skills(), [])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_agent_loop -v`
Expected: FAIL (no skill saved — distill/save not wired yet).

- [ ] **Step 3: Implement the `_finish` funnel in `run_loop`**

Define a nested helper just before the `for step` loop:

```python
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
```

Route **every** `return assets, findings, X` inside `run_loop` through it. Specifically replace:
- `return assets, findings, "agent_no_reasoner: ..."` → `return _finish("agent_no_reasoner: reasoning ladder returned nothing")`
- `return assets, findings, f"done: {action.rationale or 'goal met'}"` → `return _finish(f"done: {action.rationale or 'goal met'}")`
- the final `return assets, findings, "stopped by operator between steps"` → `return _finish("stopped by operator between steps")`
- the final `return assets, findings, f"step budget reached ({max_steps} steps)"` → `return _finish(f"step budget reached ({max_steps} steps)")`

(`findings` is empty on `no_reasoner`, so that path saves nothing in practice; the guard `and findings` keeps it correct regardless.)

- [ ] **Step 4: Run to verify they pass (whole loop suite green)**

Run: `python3 -m unittest tests.test_agent_loop -v`
Expected: PASS (all cases).

- [ ] **Step 5: Commit**

```bash
git add modules/agent_offensive/loop.py tests/test_agent_loop.py
git commit -m "feat(agent): distill + save a skill when a run produced findings"
```

---

### Task 6: Module wiring — construct the toolbox, reindex, pass distill closure

**Files:**
- Modify: `modules/agent_offensive/module.py`
- Test: `tests/test_agent_module.py` (add a case)

**Interfaces:**
- Consumes: `Toolbox` (Task 1-2), `distill` (Task 3), `run_loop(..., toolbox, distill_fn)` (Task 4-5).
- Produces: a full agent run now reads/writes `<project_dir>/toolbox/`. `_substitutions(scope)` maps concrete in-scope targets → `{TARGET}`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_agent_module.py  (imports at top of file as needed)
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from atpt.module import RunContext
from modules.agent_offensive.module import AgentOffensive
from atpt.module import Manifest


def _manifest():
    return Manifest(id="agent_offensive", name="Agent", phase="recon",
                    entrypoint="module:AgentOffensive", intrusive=True)


class _Reasoner:
    """Scripted: first the loop step, then the distillation skill JSON."""
    def __init__(self, steps):
        self._it = iter(steps)

    def reason(self, prompt, phase):
        class R:
            text = next(self._it)
        return R()


class ModuleToolboxTest(unittest.TestCase):
    def test_successful_run_persists_a_skill_file(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pd = Path(tmp.name)

        # A fake store: only the pieces the module/ctx touch.
        class Store:
            def add_event(self, *a, **k): pass

        eng = {"id": "e1", "config": json.dumps({"offensive_agent": {"enabled": True,
                "max_steps": 3, "allow_bins": []}})}
        scope = {"in_scope_cidrs": ["10.1.1.5/32"]}
        # Keep it to command-then-done (no session step — that would touch the real
        # session module). The nmap output carries a flag the loop's flag-scanner
        # turns into a finding, so the run "succeeds" and distillation fires.
        steps = [
            '{"command":["nmap","-Pn","10.1.1.5"]}',   # step 1: output carries flag{seed}
            '{"done": true}',                           # step 2: end
            # distillation reply (loop ended with a finding):
            '{"name":"nmap-open","applies_to":{"service_tags":["http"]},'
            '"steps":[{"command":["nmap","-Pn","10.1.1.5"]}],"success_note":"scan"}',
        ]
        ctx = RunContext(engagement=eng, scope=scope, store=Store(), project_dir=pd,
                         reasoner=_Reasoner(steps), goals="capture the flag flag{seed}")
        mod = AgentOffensive(_manifest(), pd)
        # monkeypatch execute to emit a flag in output
        import modules.agent_offensive.module as M
        orig = M.execute
        M.execute = lambda argv, timeout=300: {"rc": 0, "out": "flag{seed}", "err": ""}
        try:
            res = mod.run(ctx)
        finally:
            M.execute = orig
        self.assertTrue(res.ok)
        files = list((pd / "toolbox").glob("*.json"))
        self.assertTrue(files, "a skill file should have been written")
        self.assertEqual(json.loads(files[0].read_text())["name"], "nmap-open")
```

*(If constructing `RunContext`/`Manifest` differs from the current signatures, adjust the fakes to match — the assertion that matters is: an enabled run that captured a flag writes exactly one skill JSON under `project_dir/toolbox/`.)*

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_agent_module -v`
Expected: FAIL (no toolbox file written; module doesn't wire the toolbox yet).

- [ ] **Step 3: Wire the module**

In `modules/agent_offensive/module.py`, add imports:

```python
import ipaddress
from atpt.toolbox import Toolbox
from .distill import distill
```

Add a helper below the imports:

```python
def _substitutions(scope: dict) -> dict:
    """Map concrete in-scope single hosts to {TARGET} so distilled steps generalise."""
    subs = {}
    for d in (scope or {}).get("in_scope_domains", []) or []:
        h = str(d).lower().lstrip("*").lstrip(".")
        if h:
            subs[h] = "{TARGET}"
    for c in (scope or {}).get("in_scope_cidrs", []) or []:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            subs[str(net.network_address)] = "{TARGET}"
    return subs
```

In `run(...)`, after building `guard` and before calling `run_loop`, construct the toolbox and a distill closure:

```python
        toolbox = Toolbox(ctx.project_dir / "toolbox")
        toolbox.reindex()
        subs = _substitutions(ctx.scope)
        prov = {"engagement": ctx.engagement.get("id")}

        def distill_fn(goal, transcript):
            return distill(goal=goal, transcript=transcript,
                           reason_fn=lambda p: ctx.reason(p, "exploit"),
                           substitutions=subs, provenance=prov)
```

Pass them into `run_loop(...)`:

```python
        assets, findings, summary = run_loop(
            goal=ctx.goals or "Capture the flags on the in-scope target(s).",
            guard=guard, scope=ctx.scope, reason_fn=lambda p: ctx.reason(p, "exploit"),
            max_steps=max_steps, emit=emit,
            execute_fn=lambda argv: execute(argv, timeout=step_timeout),
            harvest_fn=harvest, toolbox=toolbox, distill_fn=distill_fn)
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_agent_module -v`
Expected: PASS.

- [ ] **Step 5: Full suite regression**

Run: `python3 -m pytest -q tests/`
Expected: all pass (baseline 281 + the new toolbox/distill/loop/module tests), no new warnings.

- [ ] **Step 6: Commit**

```bash
git add modules/agent_offensive/module.py tests/test_agent_module.py
git commit -m "feat(agent): wire the toolbox into the module (reindex, retrieve, distill-on-success)"
```

---

### Task 7: Operator-visible toolbox panel (web console)

**Files:**
- Modify: `atpt/web.py` (one global GET/DELETE route + a settings panel + a menu entry + a small loader)
- Test: `tests/test_web_toolbox.py`

**Interfaces:**
- Consumes: `Toolbox.list_skills`, `Toolbox.delete`.
- Produces: `GET /api/toolbox` → `{"skills": [...]}`; `DELETE /api/toolbox?name=<n>` → `{"deleted": bool}`; a "Toolbox" settings panel listing skills with a delete control.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_web_toolbox.py
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from atpt.web import WebApp
from atpt.toolbox import Toolbox


class WebToolboxTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.pd = Path(self._tmp.name)
        Toolbox(self.pd / "toolbox").save({
            "name": "ssh-brute", "applies_to": {"service_tags": ["ssh"]},
            "steps": [{"command": ["hydra", "{TARGET}"]}], "success_note": "brute"})
        self.app = WebApp(self.pd)

    def tearDown(self):
        self._tmp.cleanup()

    def test_get_lists_skills(self):
        status, ctype, body, _ = self.app._route("GET", "/api/toolbox", {}, None)
        self.assertEqual(status, 200)
        self.assertIn(b"ssh-brute", body)

    def test_delete_removes_skill(self):
        status, _, body, _ = self.app._route("DELETE", "/api/toolbox",
                                              {"name": ["ssh-brute"]}, None)
        self.assertEqual(status, 200)
        self.assertEqual(Toolbox(self.pd / "toolbox").list_skills(), [])
```

*(Query values arrive as lists from the stdlib query parser; if this app normalises them differently, match the existing convention used by other routes.)*

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_web_toolbox -v`
Expected: FAIL (route returns 404/unknown).

- [ ] **Step 3: Add the route**

In `atpt/web.py` `_route`, in the **global (non-eid) section** (near `/api/settings`, before the `if path.startswith("/api/") and not eid:` guard), add:

```python
        if path == "/api/toolbox":
            tb = Toolbox(self.project_dir / "toolbox")
            if method == "GET":
                return self._json(200, {"skills": tb.list_skills()})
            if method == "DELETE":
                name = (query.get("name") or [""])[0] if isinstance(query.get("name"), list) \
                    else query.get("name", "")
                return self._json(200, {"deleted": tb.delete(name)})
            return self._json(405, {"error": "GET or DELETE"})
```

Add the import at the top of `web.py`: `from atpt.toolbox import Toolbox`.

- [ ] **Step 4: Add the settings panel + menu entry + loader (HTML/JS)**

Add a panel inside the settings sheet (next to the other `data-panel` divs, e.g. after the `report` panel):

```html
        <div class="panel hidden" data-panel="toolbox">
          <h3>Strategy Toolbox <span class="mut">— learned skills</span></h3>
          <p class="mut">Skills the agent distilled from successful runs. They only
             suggest commands; every command is still scope-checked. Files live in
             <code>toolbox/</code> and are hand-editable.</p>
          <div id="tbList" class="col" style="gap:8px"></div>
        </div>
```

Add a menu entry near the other `openSettings(...)` bindings (mirroring `#menuScope`):

```html
      <a href="#" id="menuToolbox">Toolbox</a>
```
```javascript
$('#menuToolbox').onclick=()=>openSettings('toolbox');
```

In `openSettings(tab)`, when `tab==='toolbox'`, load the list:

```javascript
  if(tab==='toolbox'){
    const {skills}=await api('/api/toolbox');
    const box=$('#tbList');
    box.innerHTML = (skills&&skills.length)? '' : '<div class="mut">No skills yet — run the agent to a win.</div>';
    (skills||[]).forEach(s=>{
      const st=(s.applies_to&&s.applies_to.service_tags||[]).join(', ');
      const div=document.createElement('div'); div.className='card';
      div.innerHTML=`<b>${s.name}</b> <span class="mut">${st}</span><br>`+
        `<span class="mut">${s.success_note||''}</span>`;
      const del=document.createElement('button'); del.textContent='Delete'; del.className='sm';
      del.onclick=async()=>{ await api('/api/toolbox?name='+encodeURIComponent(s.name),{method:'DELETE'}); openSettings('toolbox'); };
      div.appendChild(document.createElement('br')); div.appendChild(del);
      box.appendChild(div);
    });
  }
```

*(Match the exact class names/`api()` helper the file already uses; the above follows the patterns seen in `web.py`. HTML/JS is verified visually in Task 9, not by unit test.)*

- [ ] **Step 5: Run to verify the route test passes + full suite**

Run: `python3 -m unittest tests.test_web_toolbox -v && python3 -m pytest -q tests/`
Expected: PASS / all pass.

- [ ] **Step 6: Commit**

```bash
git add atpt/web.py tests/test_web_toolbox.py
git commit -m "feat(web): operator-visible Toolbox panel (/api/toolbox list + delete)"
```

---

### Task 8: README rewrite — new agent + toolbox workflow

**Files:**
- Modify: `README.md`
- Reference: `docs/CORE.md` (deep tech already lives here — keep the README UI/workflow-focused and point to CORE for internals).

- [ ] **Step 1: Rewrite the workflow section**

Update `README.md` so a new user can follow the **current** app, not the old classic-chain pipeline. Cover, in order:
1. Install / launch (`atpt desktop` / `atpt serve`; the desktop app window).
2. Create an engagement: enter scope + an **explicit target** (required).
3. Turn on the **offensive agent** (Settings → CTF/agent toggle) and set the goal.
4. **RUN** connects the VPN; the **one-time scope-confirmation gate** echoes the resolved targets — confirm before any packet is sent (all modes, including full).
5. The agent's ReAct loop: enumerate → exploit → foothold (reverse-shell listener + session) → privesc → flags; events/findings fill live; **STOP** halts between steps and tears down the VPN.
6. **Strategy Toolbox (new):** on a win the agent distills the winning steps into a reusable skill under `toolbox/`; on later targets matching skills are injected as a LEARNED PLAYBOOK. Skills are hand-editable JSON and visible under Settings → Toolbox. Safety: a skill only suggests; every command is still scope-checked.
7. Report: PTES Markdown download.

- [ ] **Step 2: Add a short "Strategy Toolbox" subsection**

Document: where skills live (`<data home>/toolbox/*.json`), the skill shape (`name`, `applies_to.{goal_tags,service_tags}`, `steps`, `success_note`, `provenance`), how to share one (copy the JSON file in — `reindex` picks it up on next run), and the safety guarantee.

- [ ] **Step 3: Commit (screenshots added next task)**

```bash
git add README.md
git commit -m "docs(readme): rewrite for the agent + scope-gate + toolbox workflow"
```

---

### Task 9: New screenshots

**Files:**
- Create/replace: `docs/screenshots/*.png`
- Modify: `README.md` (embed the new images)

Capture from the running app using the in-app browser (built-in browser pane). No live exploit is required — seed data so the panels are populated.

- [ ] **Step 1: Launch the console with seeded data**

- Start the web console on loopback (e.g. `atpt serve` / `make_server` on a free 127.0.0.1 port).
- Seed a demo engagement via the existing `POST /api/demo` (populates assets/findings/tree).
- Seed one toolbox skill so the panel is non-empty (drop a JSON file into `<project_dir>/toolbox/` or run the seeded-skill helper), then open the app.

- [ ] **Step 2: Screenshot the key states** (built-in browser: `navigate` + `computer` screenshot)

Capture and save to `docs/screenshots/`:
1. `agent-toggle.png` — Settings → CTF/agent toggle + goal.
2. `scope-confirm.png` — the scope-confirmation gate showing resolved targets.
3. `agent-run.png` — events feed + findings table (flags) mid/after a run.
4. `toolbox-panel.png` — Settings → Toolbox listing a learned skill.

- [ ] **Step 3: Embed in README + commit**

Reference the four images in the workflow section written in Task 8.

```bash
git add docs/screenshots/*.png README.md
git commit -m "docs(readme): new screenshots — agent workflow, scope gate, toolbox panel"
```

---

### Task 10: Verify, integrate, push to GitHub

**Files:** none (integration + release).

- [ ] **Step 1: Full suite green**

Run: `python3 -m pytest -q tests/`
Expected: all pass. Record the count.

- [ ] **Step 2: Integrate the branch**

Use the **superpowers:finishing-a-development-branch** skill to decide/execute integration. Expected path (matches project history): fast-forward/merge `feat/llm-offensive-agent` → `main` locally, keeping history.

```bash
git checkout main && git merge --no-ff feat/llm-offensive-agent
python3 -m pytest -q tests/   # re-verify on main
```

- [ ] **Step 3: Push to GitHub**

Confirm the remote, then push `main` (origin = `git@github.com:avitwil/ATPTmaster.git`, SSH):

```bash
git remote -v
git push origin main
```

- [ ] **Step 4: Report**

Report the pushed commit SHA, the test count, and the four screenshots added. Do not claim success without the `git push` output and a green suite.

---

## Self-Review

**Spec coverage (Phase 2 section):**
- "distilled into a reusable skill and saved to a toolbox" → Tasks 3, 5, 6.
- skill shape `{name, applies_to, steps, provenance, success_note}` → Task 1 (`save` normalises exactly this shape) + Task 3 (distill emits it).
- "persisted (store table or files under the data home)" → files under `<project_dir>/toolbox/` + SQLite index (Task 1); user-refined to **files + index**.
- "save-on-success … operator-visible and editable" → Task 5 (save on findings), Task 7 (panel), files are hand-editable JSON.
- "retrieve … keyword/tag match, stdlib-only — no embeddings … inject top matches" → Task 2 (ranking), Task 4 (inject top-2).
- "a skill only suggests … every command still passes ScopeGuard … can never widen scope" → unchanged execution path; Global Constraints; asserted implicitly (Task 4/5 route commands through the existing `guard.vet`).
- User asks beyond the spec: README rewrite + new screenshots + push → Tasks 8, 9, 10.

**Placeholder scan:** none — every code step carries real code; screenshot/README steps enumerate concrete artifacts.

**Type consistency:** `Toolbox.save/list_skills/get/delete/reindex/search`, `slugify`, `goal_tags`, `service_tags_from_assets`, `distill(*, goal, transcript, reason_fn, substitutions, provenance)`, `last_json`, `run_loop(..., toolbox=None, distill_fn=None)` — names/signatures are used identically across Tasks 1-7. The skill dict keys (`name`, `applies_to.{goal_tags,service_tags}`, `steps[].command/note`, `success_note`, `provenance`, `updated_at`) are consistent between distill (producer) and toolbox.save (normaliser/consumer).
