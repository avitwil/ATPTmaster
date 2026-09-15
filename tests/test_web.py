"""Web console routing — exercised through WebApp.handle (no sockets)."""
import json
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore
from atpt.web import WebApp, valid_eid


class WebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "atpt.db"
        # project_dir="." so modules/ resolves; db isolated in a temp file
        self.app = WebApp(".", db_path=self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def _get(self, path, **q):
        qs = {k: str(v) for k, v in q.items()}
        return self.app.handle("GET", path, qs, b"")

    def _post(self, path, obj):
        return self.app.handle("POST", path, {}, json.dumps(obj).encode())

    def test_index_served(self):
        st, ct, body, _ = self._get("/")
        self.assertEqual(st, 200)
        self.assertIn("text/html", ct)
        self.assertIn(b"ATPTmaster", body)

    def test_create_requires_scope_target(self):
        st, _, body, _ = self._post("/api/engagement", {"engagement": "x", "scope": {}})
        self.assertEqual(st, 400)
        self.assertIn("in-scope", json.loads(body)["error"])

    def test_create_and_list_engagement(self):
        st, _, body, _ = self._post("/api/engagement", {
            "engagement": "acme", "name": "Acme",
            "scope": {"in_scope_domains": ["acme.com"]}, "mode": "semi"})
        self.assertEqual(st, 200)
        _, _, lst, _ = self._get("/api/engagements")
        ids = [e["id"] for e in json.loads(lst)["engagements"]]
        self.assertIn("acme", ids)

    def test_demo_seeds_assets(self):
        st, _, body, _ = self._post("/api/demo", {})
        self.assertEqual(st, 200)
        _, _, s, _ = self._get("/api/status", eng="demo")
        self.assertEqual(json.loads(s)["assets"], 4)

    def test_run_dry_run_does_not_mutate_or_shell(self):
        self._post("/api/demo", {})
        st, _, body, _ = self._post("/api/run", {"eng": "demo", "mode": "full", "dry_run": True})
        self.assertEqual(st, 200)
        res = json.loads(body)
        self.assertIn("map_ptt", res["result"]["executed"])   # ran in dry-run
        self.assertEqual(res["status"]["findings"], 0)         # nothing persisted

    def test_findings_tree_and_report(self):
        self._post("/api/engagement", {"engagement": "e1", "name": "E1",
                                       "scope": {"in_scope_domains": ["e1.com"]}})
        store = SQLiteStore(self.db)
        store.upsert_finding("e1", {"title": "Exposed data service (redis)", "severity": "high",
                                    "cvss": 7.5, "owasp": "A05", "domain": "Infra",
                                    "status": "validated", "evidence": {"asset_value": "h:6379"}})
        store.upsert_finding("e1", {"title": "Noise", "severity": "low", "domain": "Web",
                                    "status": "false_positive", "evidence": {"rule": "web_generic"}})

        _, _, fbody, _ = self._get("/api/findings", eng="e1")
        titles = [f["title"] for f in json.loads(fbody)["findings"]]
        self.assertIn("Exposed data service (redis)", titles)
        self.assertIsInstance(json.loads(fbody)["findings"][0]["evidence"], dict)  # parsed

        _, _, tbody, _ = self._get("/api/tree", eng="e1")
        tree = json.loads(tbody)
        doms = [b["domain"] for b in tree["branches"]]
        self.assertIn("Infra", doms)
        self.assertNotIn("Web", doms)   # false-positive-only domain excluded

        st, ct, rbody, headers = self._get("/api/report", eng="e1")
        self.assertEqual(st, 200)
        self.assertIn("markdown", ct)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        self.assertIn(b"Exposed data service (redis)", rbody)

    def test_chat_status_reply(self):
        self._post("/api/demo", {})
        _, _, body, _ = self._post("/api/chat", {"eng": "demo", "message": "status"})
        self.assertIn("assets=4", json.loads(body)["reply"])

    def test_missing_engagement_404(self):
        st, _, _, _ = self._get("/api/status", eng="nope")
        self.assertEqual(st, 404)

    def test_valid_eid_rejects_traversal_and_junk(self):
        for bad in ("", ".", "..", "../etc", "a/b", "a\\b", "x" * 65, "a b", "a.b"):
            self.assertFalse(valid_eid(bad), bad)
        for ok in ("acme-2026", "demo", "E1_test"):
            self.assertTrue(valid_eid(ok), ok)

    def test_create_rejects_path_traversal_id(self):
        st, _, body, _ = self._post("/api/engagement", {
            "engagement": "../../../../tmp/pwn", "scope": {"in_scope_domains": ["x.com"]}})
        self.assertEqual(st, 400)

    def test_bad_json_body_is_400(self):
        st, _, body, _ = self.app.handle("POST", "/api/engagement", {}, b"{not json")
        self.assertEqual(st, 400)
        self.assertIn("invalid JSON", json.loads(body)["error"])
