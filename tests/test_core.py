"""Proves the engine's run-mode + approval-gating contract without any tools."""
import json
import tempfile
import unittest
from pathlib import Path

from atpt.engine import Orchestrator
from atpt.module import Manifest, Module, ModuleResult
from atpt.state import SQLiteStore


class _Fake(Module):
    """Fake module whose run() yields a fixed result, to exercise the engine."""
    def __init__(self, manifest, result):
        super().__init__(manifest, Path("."))
        self._result = result

    def run(self, ctx):
        return self._result


def _mods():
    a = _Fake(Manifest(id="a_recon", name="A", phase="recon", entrypoint="x",
                       consumes=["target"], provides=["asset"], intrusive=False),
              ModuleResult(assets=[{"asset_type": "host", "value": "h1"}], summary="a"))
    b = _Fake(Manifest(id="b_exploit", name="B", phase="exploit", entrypoint="x",
                       consumes=["asset"], intrusive=True),
              ModuleResult(findings=[{"title": "boom"}], summary="b"))
    return {"a_recon": a, "b_exploit": b}


class CoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {"in_scope_domains": ["x.com"]}, "s.json", "full", {})
        self.eng = self.store.get_engagement("E")
        self.orch = Orchestrator(self.store, _mods(), Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_cascades_through_dependency(self):
        res = self.orch.run(self.eng, "full")
        self.assertEqual(res["executed"], ["a_recon", "b_exploit"])   # b unlocked by a's asset
        self.assertEqual(self.store.count_assets("E"), 1)
        self.assertEqual(self.store.count_findings("E"), 1)

    def test_semi_gates_intrusive_then_resumes(self):
        r1 = self.orch.run(self.eng, "semi")
        self.assertEqual(r1["executed"], ["a_recon"])                 # ran non-intrusive
        self.assertEqual(r1["gated_on"], "b_exploit")                 # paused at intrusive
        self.assertTrue(self.store.pending_approvals("E"))
        self.store.resolve_approval("E", "b_exploit", "approved")
        r2 = self.orch.run(self.eng, "semi")
        self.assertEqual(r2["executed"], ["b_exploit"])               # resumed after approval

    def test_step_runs_exactly_one(self):
        r = self.orch.run(self.eng, "step")
        self.assertEqual(len(r["executed"]), 1)

    def test_dry_run_mutates_nothing(self):
        res = self.orch.run(self.eng, "full", dry_run=True)
        self.assertEqual(res["executed"], ["a_recon"])               # b stays locked (no real asset)
        self.assertEqual(self.store.count_assets("E"), 0)            # State Tree untouched


if __name__ == "__main__":
    unittest.main(verbosity=2)
