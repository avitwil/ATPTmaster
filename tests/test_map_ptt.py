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
