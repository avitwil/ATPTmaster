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
        self.build = _rep.build_report_md
        self.eid = "E"

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
