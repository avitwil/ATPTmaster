"""report_ptes — PTES Markdown rendering + on-demand build helper."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

from atpt.module import RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore

_spec = importlib.util.spec_from_file_location(
    "report_ptes_mod", Path("modules/report_ptes/module.py"))
_rep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rep)


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pd = Path(self.tmp.name)
        self.store = SQLiteStore(self.pd / "var" / "atpt.db")
        self.store.create_engagement("E", "Acme Test",
                                     {"in_scope_domains": ["acme.com"]}, "s.json", "full", {})
        self.store.upsert_asset("E", {"asset_type": "service", "value": "h:6379", "service": "redis"})
        self.store.upsert_finding("E", {"title": "Exposed data service (redis)", "severity": "high",
                                        "cvss": 7.5, "owasp": "A05", "status": "validated",
                                        "evidence": {"asset_value": "h:6379", "rule": "exposed_data_service"}})
        self.store.upsert_finding("E", {"title": "Noise", "severity": "low", "owasp": "A03",
                                        "status": "false_positive", "evidence": {"rule": "web_generic"}})
        mods = discover(Path("modules"), Path("."))
        self.assertIn("report_ptes", mods)
        self.rep = mods["report_ptes"]

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, dry_run=False):
        return RunContext(engagement=self.store.get_engagement("E"), scope={},
                          store=self.store, project_dir=self.pd, dry_run=dry_run)

    def test_build_report_md_contains_ptes_sections(self):
        md = _rep.build_report_md(self.store, "E", self.pd)
        self.assertIn("# Penetration Test Report", md)
        self.assertIn("Executive Summary", md)
        self.assertIn("Exposed data service (redis)", md)
        self.assertIn("A05", md)
        self.assertIn("7.5", md)          # CVSS surfaced
        self.assertIn("Remediation", md)

    def test_report_excludes_false_positives(self):
        md = _rep.build_report_md(self.store, "E", self.pd)
        self.assertNotIn("Noise", md)

    def test_run_writes_file(self):
        self.rep.run(self._ctx())
        out = self.pd / "var" / "reports" / "E.md"
        self.assertTrue(out.exists())
        self.assertIn("Exposed data service (redis)", out.read_text())

    def test_dry_run_writes_nothing(self):
        self.rep.run(self._ctx(dry_run=True))
        self.assertFalse((self.pd / "var" / "reports" / "E.md").exists())
