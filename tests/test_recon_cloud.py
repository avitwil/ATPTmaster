"""recon_cloud — prowler wrapper: config-gated, no-op if absent, pure parser tested."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

from atpt import toolwrap
from atpt.module import RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore

_spec = importlib.util.spec_from_file_location(
    "recon_cloud_mod", Path("modules/recon_cloud/module.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class ReconCloudTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        mods = discover(Path("modules"), Path("."))
        self.assertIn("recon_cloud", mods)
        self.mod = mods["recon_cloud"]
        self._orig = toolwrap.run
        self.addCleanup(lambda: setattr(toolwrap, "run", self._orig))

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, config, dry_run=False):
        self.store.create_engagement("E", "E", {}, "s.json", "full", config)
        return RunContext(engagement=self.store.get_engagement("E"), scope={},
                          store=self.store, project_dir=Path("."), dry_run=dry_run)

    def test_parse_prowler_keeps_only_fails(self):
        text = ('{"status_code":"FAIL","severity":"high","finding_info":{"title":"S3 public"}}\n'
                '{"status_code":"PASS","severity":"low","finding_info":{"title":"ok"}}\n')
        out = _mod.parse_prowler(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["title"], "S3 public")
        self.assertEqual(out[0]["domain"], "Cloud")

    def test_no_cloud_config_skips(self):
        res = self.mod.run(self._ctx({}))
        self.assertIn("no cloud target", res.summary)

    def test_missing_binary_noops(self):
        toolwrap.run = lambda argv, timeout=300: (-1, "", "prowler not installed")
        res = self.mod.run(self._ctx({"cloud": {"provider": "aws"}}))
        self.assertIn("not installed", res.summary)

    def test_parses_findings_from_run(self):
        toolwrap.run = lambda argv, timeout=300: (
            0, '{"status_code":"FAIL","severity":"medium","finding_info":{"title":"Open SG"}}\n', "")
        res = self.mod.run(self._ctx({"cloud": {"provider": "aws"}}))
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["title"], "Open SG")
