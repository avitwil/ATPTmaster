"""Engine run control: a control() hook halts the cascade between modules."""
import tempfile
import unittest
from pathlib import Path

from atpt.engine import Orchestrator
from atpt.registry import discover
from atpt.state import SQLiteStore


class RunControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "atpt.db")
        self.store.create_engagement("demo", "Demo", {"in_scope_domains": ["demo.local"]},
                                     "demo.scope.json", "full", {})
        self.store.upsert_asset("demo", {"asset_type": "web_endpoint", "value": "http://demo.local",
                                         "host": "demo.local", "url": "http://demo.local"})
        self.orch = Orchestrator(self.store, discover(Path("modules"), Path(".")), Path("."))

    def tearDown(self):
        self.tmp.cleanup()

    def test_control_false_halts_before_any_module(self):
        # control False -> nothing runs (mode irrelevant, no scanners invoked)
        res = self.orch.run(self.store.get_engagement("demo"), "full", control=lambda: False)
        self.assertEqual(res["executed"], [])
        self.assertTrue(res["halted"])

    def test_without_control_runs_modules(self):
        # semi gates before intrusive scanners -> fast, no real nuclei/sqlmap
        res = self.orch.run(self.store.get_engagement("demo"), "semi")
        self.assertTrue(res["executed"])
        self.assertFalse(res["halted"])

    def test_control_stops_after_first_module(self):
        calls = {"n": 0}

        def control():
            calls["n"] += 1
            return calls["n"] <= 1          # allow one boundary, then halt
        res = self.orch.run(self.store.get_engagement("demo"), "semi", control=control)
        self.assertEqual(len(res["executed"]), 1)
        self.assertTrue(res["halted"])
