"""End-to-end: recon output (seeded) → map → validate → report, via the engine."""
import tempfile
import unittest
from pathlib import Path

from atpt.engine import Orchestrator
from atpt.registry import discover
from atpt.state import SQLiteStore


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pd = Path(self.tmp.name)
        self.store = SQLiteStore(self.pd / "var" / "atpt.db")
        self.store.create_engagement("E", "Acme", {"in_scope_domains": ["acme.com"]},
                                     "s.json", "full", {})
        # seed what recon would have produced (no live tools in tests)
        self.store.upsert_asset("E", {"asset_type": "service", "value": "10.0.0.5:6379",
                                      "service": "redis"})
        self.store.upsert_asset("E", {"asset_type": "web_endpoint", "value": "http://acme.com",
                                      "url": "http://acme.com"})
        mods = discover(Path("modules"), Path("."))
        # exclude recon_nebula (would shell out); run the reasoning/report pipeline only
        self.mods = {k: mods[k] for k in ("map_ptt", "validate_xalgorix", "report_ptes")}
        self.orch = Orchestrator(self.store, self.mods, self.pd)

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_pipeline_maps_validates_and_reports(self):
        res = self.orch.run(self.store.get_engagement("E"), "full")
        self.assertEqual(res["executed"], ["map_ptt", "validate_xalgorix", "report_ptes"])
        self.assertGreater(self.store.count_findings("E"), 0)            # map produced candidates
        self.assertGreater(self.store.count_findings("E", status="validated"), 0)  # validate promoted
        report = self.pd / "var" / "reports" / "E.md"
        self.assertTrue(report.exists())
        text = report.read_text()
        self.assertIn("Penetration Test Report", text)
        self.assertIn("redis", text)                                    # the high-sev finding is reported

    def test_dry_run_pipeline_mutates_nothing(self):
        self.orch.run(self.store.get_engagement("E"), "full", dry_run=True)
        self.assertEqual(self.store.count_findings("E"), 0)
        self.assertFalse((self.pd / "var" / "reports" / "E.md").exists())
