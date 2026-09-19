"""Engine wiring: global-reasoning fallback + CTF goals into the run context."""
import json
import tempfile
import unittest
from pathlib import Path

from atpt.engine import Orchestrator
from atpt.module import RunContext
from atpt.reasoning import ReasoningResult
from atpt.state import SQLiteStore


class _RecordingLadder:
    def __init__(self):
        self.prompt = None

    def reason(self, prompt, phase, role=None):
        self.prompt = prompt
        return ReasoningResult(text="ok", provider="p")


class EngineSettingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "atpt.db")
        self.orch = Orchestrator(self.store, {}, ".")

    def tearDown(self):
        self.tmp.cleanup()

    def _eng(self, config):
        self.store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                     "e1.scope.json", "semi", config)
        return self.store.get_engagement("e1")

    def test_falls_back_to_global_reasoning(self):
        self.store.set_settings({"reasoning": {
            "providers": {"g": {"backend": "ollama", "model": "llama3.1"}},
            "preference": ["g"]}})
        ctx = self.orch._ctx(self._eng({}), dry_run=False)
        self.assertEqual(ctx.reasoner.preference, ["g"])

    def test_engagement_reasoning_overrides_global(self):
        self.store.set_settings({"reasoning": {"providers": {"g": {}}, "preference": ["g"]}})
        ctx = self.orch._ctx(self._eng({"reasoning": {"providers": {"e": {}}, "preference": ["e"]}}),
                             dry_run=False)
        self.assertEqual(ctx.reasoner.preference, ["e"])

    def test_goals_passed_into_context(self):
        ctx = self.orch._ctx(self._eng({"ctf": {"goals": "find the flag in /root"}}), dry_run=False)
        self.assertEqual(ctx.goals, "find the flag in /root")

    def test_goals_prepended_to_prompt(self):
        lad = _RecordingLadder()
        ctx = RunContext(engagement={"id": "e1"}, scope={}, store=self.store,
                         project_dir=Path("."), reasoner=lad, goals="pwn the box")
        ctx.reason("enumerate services", "map")
        self.assertIn("pwn the box", lad.prompt)
        self.assertIn("enumerate services", lad.prompt)

    def test_no_goals_leaves_prompt_untouched(self):
        lad = _RecordingLadder()
        ctx = RunContext(engagement={"id": "e1"}, scope={}, store=self.store,
                         project_dir=Path("."), reasoner=lad)
        ctx.reason("just this", "map")
        self.assertEqual(lad.prompt, "just this")
