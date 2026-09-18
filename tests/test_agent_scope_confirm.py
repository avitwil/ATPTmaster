import json
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore
from atpt.web import WebApp


class ScopeConfirmTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbp = Path(self.tmp.name) / "atpt.db"
        self.app = WebApp(".", db_path=self.dbp)
        self.app.handle("POST", "/api/engagement", {}, json.dumps({
            "engagement": "e1", "mode": "full",
            "scope": {"domains": {"infra": {"enabled": True, "in": ["10.1.1.5"]}}}}).encode())
        # opt the engagement into the offensive agent
        SQLiteStore(self.dbp).update_engagement_config("e1", {"offensive_agent": {"enabled": True}})

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_requires_scope_confirm_first(self):
        _, _, body, _ = self.app.handle("POST", "/api/run/start", {"eng": "e1"},
                                        json.dumps({"eng": "e1"}).encode())
        r = json.loads(body)
        self.assertTrue(r.get("needs_scope_confirm"))
        self.assertIn("10.1.1.5", r["targets"])

    def test_confirm_hash_lets_it_proceed(self):
        _, _, b1, _ = self.app.handle("POST", "/api/run/start", {"eng": "e1"},
                                      json.dumps({"eng": "e1"}).encode())
        h = json.loads(b1)["hash"]
        _, _, body, _ = self.app.handle("POST", "/api/run/start", {"eng": "e1"},
                                        json.dumps({"eng": "e1", "scope_confirm": h}).encode())
        # proceeds past the scope gate — must NOT re-ask scope
        self.assertFalse(json.loads(body).get("needs_scope_confirm"))


if __name__ == "__main__":
    unittest.main()
