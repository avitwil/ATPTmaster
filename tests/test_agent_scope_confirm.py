import json
import tempfile
import time
import unittest
from pathlib import Path

from atpt.state import SQLiteStore
from atpt.web import WebApp


class ScopeConfirmTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbp = Path(self.tmp.name) / "atpt.db"
        # project_dir is a tmp dir, not ".": a confirm-hash run below starts a
        # real background thread (WebApp._start_run), and with project_dir="."
        # that thread's Orchestrator discovers the REAL modules/agent_offensive,
        # which mkdirs a Toolbox at project_dir/toolbox — polluting the repo
        # root. A tmp project_dir has no modules/ to discover (Path.glob on a
        # missing dir just yields nothing), so the run finds no module to
        # execute and nothing gets created; the scope-confirm assertions below
        # only look at the immediate JSON response, never at a module actually
        # having run, so this doesn't weaken the test's intent.
        self.proj = tempfile.TemporaryDirectory()
        self.app = WebApp(self.proj.name, db_path=self.dbp)
        self.app.handle("POST", "/api/engagement", {}, json.dumps({
            "engagement": "e1", "mode": "full",
            "scope": {"domains": {"infra": {"enabled": True, "in": ["10.1.1.5"]}}}}).encode())
        # opt the engagement into the offensive agent
        SQLiteStore(self.dbp).update_engagement_config("e1", {"offensive_agent": {"enabled": True}})

    def tearDown(self):
        # Settle any background run started by the confirm-hash test (join by
        # polling /api/run/status, same idiom as test_web_settings.py's
        # background-run test) before the tmp dirs disappear out from under
        # its thread — belt-and-braces alongside the tmp project_dir above.
        for _ in range(50):
            _, _, body, _ = self.app.handle("GET", "/api/run/status", {"eng": "e1"}, b"")
            if json.loads(body)["status"] in ("idle", "done", "stopped", "paused", "gated"):
                break
            time.sleep(0.05)
        self.tmp.cleanup()
        self.proj.cleanup()

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
