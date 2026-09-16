"""map_llm — flags LLM/chat surfaces; ignores ordinary web assets."""
import tempfile
import unittest
from pathlib import Path

from atpt.module import RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore


class MapLLMTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {}, "s.json", "full", {})
        mods = discover(Path("modules"), Path("."))
        self.assertIn("map_llm", mods)
        self.mod = mods["map_llm"]
        self.assertFalse(self.mod.manifest.intrusive)

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, dry_run=False):
        return RunContext(engagement=self.store.get_engagement("E"), scope={},
                          store=self.store, project_dir=Path("."), dry_run=dry_run)

    def test_flags_chat_app(self):
        self.store.upsert_asset("E", {"asset_type": "web_path",
                                      "value": "http://acme.com/api/chat",
                                      "url": "http://acme.com/api/chat"})
        res = self.mod.run(self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["domain"], "LLM")
        self.assertEqual(res.findings[0]["owasp"], "LLM01")

    def test_ignores_plain_web(self):
        self.store.upsert_asset("E", {"asset_type": "web_endpoint",
                                      "value": "http://acme.com", "url": "http://acme.com",
                                      "http_title": "Acme Store"})
        res = self.mod.run(self._ctx())
        self.assertEqual(res.findings, [])

    def test_detects_via_title(self):
        self.store.upsert_asset("E", {"asset_type": "web_endpoint",
                                      "value": "http://acme.com/x", "url": "http://acme.com/x",
                                      "http_title": "Acme AI Assistant"})
        res = self.mod.run(self._ctx())
        self.assertEqual(len(res.findings), 1)

    def test_dry_run_plans_only(self):
        self.store.upsert_asset("E", {"asset_type": "web_path", "value": "http://acme.com/chat",
                                      "url": "http://acme.com/chat"})
        res = self.mod.run(self._ctx(dry_run=True))
        self.assertTrue(res.planned)
        self.assertEqual(res.findings, [])
