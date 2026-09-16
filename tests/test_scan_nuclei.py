"""scan_nuclei — active scan wrapper: scope-filtered, parses JSONL, no-op if absent."""
import tempfile
import unittest
from pathlib import Path

from atpt import toolwrap
from atpt.module import RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore

_NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-1","info":{"name":"Example RCE","severity":"high"},'
    '"matched-at":"http://acme.com/x","host":"acme.com"}\n'
)


class ScanNucleiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.scope = {"in_scope_domains": ["acme.com"]}
        self.store.create_engagement("E", "E", self.scope, "s.json", "full", {})
        self.store.upsert_asset("E", {"asset_type": "web_endpoint",
                                      "value": "http://acme.com", "url": "http://acme.com"})
        mods = discover(Path("modules"), Path("."))
        self.assertIn("scan_nuclei", mods)
        self.mod = mods["scan_nuclei"]
        self.assertTrue(self.mod.manifest.intrusive)
        self._orig = toolwrap.run
        self.addCleanup(lambda: setattr(toolwrap, "run", self._orig))

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, dry_run=False):
        return RunContext(engagement=self.store.get_engagement("E"), scope=self.scope,
                          store=self.store, project_dir=Path("."), dry_run=dry_run)

    def test_dry_run_plans_only(self):
        toolwrap.run = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run"))
        res = self.mod.run(self._ctx(dry_run=True))
        self.assertTrue(res.planned)
        self.assertEqual(res.findings, [])

    def test_missing_binary_noops(self):
        toolwrap.run = lambda argv, timeout=300: (-1, "", "nuclei not installed")
        res = self.mod.run(self._ctx())
        self.assertEqual(res.findings, [])
        self.assertIn("not installed", res.summary)

    def test_parses_jsonl_into_findings(self):
        toolwrap.run = lambda argv, timeout=300: (0, _NUCLEI_JSONL, "")
        res = self.mod.run(self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f["title"], "Example RCE")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["source_tool"], "nuclei")

    def test_out_of_scope_asset_not_scanned(self):
        self.store.upsert_asset("E", {"asset_type": "web_endpoint",
                                      "value": "http://evil.com", "url": "http://evil.com"})
        seen = []
        def fake(argv, timeout=300):
            seen.append(argv)
            return (0, "", "")
        toolwrap.run = fake
        self.mod.run(self._ctx())
        joined = " ".join(" ".join(a) for a in seen)
        self.assertNotIn("evil.com", joined)
        self.assertIn("acme.com", joined)
