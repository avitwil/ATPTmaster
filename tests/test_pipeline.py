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


class FailedModuleNotCompletedTest(unittest.TestCase):
    """A module that runs but reports ok=False must NOT count as completed, so it
    re-runs next time instead of wedging the pipeline (the recon exit=2 bug)."""

    def test_ok_false_is_not_marked_completed(self):
        from atpt.module import Manifest, Module, ModuleResult
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pd = Path(tmp.name)
        store = SQLiteStore(pd / "var" / "atpt.db")
        store.create_engagement("E", "Acme", {"in_scope_cidrs": ["10.0.0.1"]},
                                "s.json", "full", {})

        class Flaky(Module):
            manifest = Manifest(id="recon_flaky", name="Flaky", phase="recon",
                                entrypoint="x", consumes=["target"])
            def run(self, ctx):
                return ModuleResult(assets=[], summary="scanner failed", ok=False)

        mod = Flaky(Flaky.manifest, pd)
        orch = Orchestrator(store, {"recon_flaky": mod}, pd)
        eng = store.get_engagement("E")
        orch.run(eng, "full")
        self.assertNotIn("recon_flaky", store.completed_modules("E"))  # not "done"
        # still pending -> would run again
        self.assertIn("recon_flaky", [m.manifest.id for m in orch._pending(eng, "full")])
