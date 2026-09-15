"""validate_xalgorix — verification-first promotion / false-positive elimination."""
import tempfile
import unittest
from pathlib import Path

from atpt.module import RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore


class ValidateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {}, "s.json", "full", {})
        mods = discover(Path("modules"), Path("."))
        self.assertIn("validate_xalgorix", mods)          # registry finds it
        self.val = mods["validate_xalgorix"]

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, dry_run=False):
        return RunContext(engagement=self.store.get_engagement("E"), scope={},
                          store=self.store, project_dir=Path("."), dry_run=dry_run)

    def _seed(self, title, severity, rule):
        self.store.upsert_finding("E", {"title": title, "severity": severity,
                                        "status": "candidate",
                                        "evidence": {"rule": rule}})

    def test_promotes_high_confidence_to_validated(self):
        self._seed("Exposed data service (redis)", "high", "exposed_data_service")
        self.val.run(self._ctx())
        self.assertEqual(self.store.count_findings("E", status="validated"), 1)

    def test_eliminates_low_confidence_as_false_positive(self):
        self._seed("Web app entry", "low", "web_generic")
        self.val.run(self._ctx())
        self.assertEqual(self.store.count_findings("E", status="validated"), 0)
        fps = self.store.list_findings("E", status="false_positive")
        self.assertEqual(len(fps), 1)

    def test_midconfidence_stays_candidate(self):
        self._seed("SSH surface", "medium", "ssh_surface")
        self.val.run(self._ctx())
        self.assertEqual(self.store.count_findings("E", status="candidate"), 1)

    def test_dry_run_mutates_nothing(self):
        self._seed("Exposed data service (redis)", "high", "exposed_data_service")
        self.val.run(self._ctx(dry_run=True))
        self.assertEqual(self.store.count_findings("E", status="validated"), 0)
        self.assertEqual(self.store.count_findings("E", status="candidate"), 1)
