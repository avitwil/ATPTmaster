"""Web console routing — exercised through WebApp.handle (no sockets)."""
import json
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore
from atpt.web import WebApp, valid_eid, _pingable_targets


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

    def test_create_rejects_enabled_domain_without_target(self):
        # enabling a scope category but leaving its input empty must NOT pass as
        # "full scope of the domain" — the user must supply a concrete target.
        st, _, body, _ = self._post("/api/engagement", {
            "engagement": "web1", "mode": "semi",
            "scope": {"domains": {"web": {"enabled": True, "in": [], "out": []}}}})
        self.assertEqual(st, 400)
        err = json.loads(body)["error"].lower()
        self.assertIn("web", err)
        self.assertIn("target", err)

    def test_create_accepts_enabled_domain_with_target(self):
        st, _, _, _ = self._post("/api/engagement", {
            "engagement": "web2", "mode": "semi",
            "scope": {"domains": {"web": {"enabled": True, "in": ["acme.com"]}}}})
        self.assertEqual(st, 200)

    def test_create_rejects_all_sentinel_as_full_scope(self):
        # 'all' is the legacy "whole domain" sentinel — it must be refused, same
        # as blank input, so scope is never silently broadened.
        st, _, body, _ = self._post("/api/engagement", {
            "engagement": "web4", "mode": "semi",
            "scope": {"domains": {"web": {"enabled": True, "in": ["all"]}}}})
        self.assertEqual(st, 400)
        self.assertIn("target", json.loads(body)["error"].lower())

    def test_create_ignores_disabled_empty_domain(self):
        # a category left disabled is not "selected" — it needs no target.
        st, _, _, _ = self._post("/api/engagement", {
            "engagement": "web3", "mode": "semi",
            "scope": {"domains": {
                "web": {"enabled": True, "in": ["acme.com"]},
                "api": {"enabled": False, "in": []}}}})
        self.assertEqual(st, 200)

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

    def test_structured_domain_scope_derives_flat_fields(self):
        st, _, body, _ = self._post("/api/engagement", {
            "engagement": "acme", "name": "Acme",
            "scope": {"domains": {
                "infra": {"enabled": True, "in": ["10.0.0.0/24"], "out": ["10.0.0.5"]},
                "web": {"enabled": True, "in": ["acme.com"], "out": ["secure.acme.com"]},
                "mobile": {"enabled": True, "in": ["app.apk"]},
            }}})
        self.assertEqual(st, 200)
        import json as _j
        scope = _j.loads(SQLiteStore(self.db).get_engagement("acme")["scope"])
        self.assertEqual(scope["in_scope_cidrs"], ["10.0.0.0/24"])
        self.assertEqual(scope["in_scope_domains"], ["acme.com"])
        self.assertEqual(scope["out_of_scope_cidrs"], ["10.0.0.5"])
        self.assertEqual(scope["out_of_scope"], ["secure.acme.com"])
        self.assertIn("mobile", scope["domains"])          # metadata preserved

    def test_pingable_targets_picks_single_hosts_only(self):
        # single IPs and domains are probeable; a /24 range and the 'all' sentinel
        # are not — we can't ping a whole range and 'all' isn't a host.
        hosts = _pingable_targets(json.dumps({
            "in_scope_domains": ["acme.com", "all"],
            "in_scope_cidrs": ["10.114.164.13", "10.0.0.0/24", "10.5.5.5/32"]}))
        self.assertIn("acme.com", hosts)
        self.assertIn("10.114.164.13", hosts)
        self.assertIn("10.5.5.5", hosts)          # /32 -> single host
        self.assertNotIn("10.0.0.0/24", hosts)    # range: not pingable
        self.assertNotIn("all", hosts)

    def test_pingable_targets_empty_on_junk(self):
        self.assertEqual(_pingable_targets("not json"), [])
        self.assertEqual(_pingable_targets({}), [])

    def test_logo_asset_served(self):
        st, ct, body, _ = self._get("/assets/logo.png")
        self.assertEqual(st, 200)
        self.assertIn("image/png", ct)
        self.assertTrue(len(body) > 100)
        self.assertEqual(body[:8], b"\x89PNG\r\n\x1a\n")   # real PNG bytes

    def test_favicon_maps_to_logo(self):
        st, ct, _, _ = self._get("/favicon.ico")
        self.assertEqual(st, 200)
        self.assertIn("image/png", ct)

    def test_asset_route_rejects_unknown_and_traversal(self):
        for bad in ("/assets/cli.py", "/assets/../cli.py", "/assets/../../etc/passwd"):
            st, _, _, _ = self._get(bad)
            self.assertEqual(st, 404, bad)

    def test_index_references_logo_and_favicon(self):
        _, _, body, _ = self._get("/")
        self.assertIn(b'href="/assets/logo.png"', body)   # favicon link
        self.assertIn(b'src="/assets/logo.png"', body)     # brand panel

    def test_bad_json_body_is_400(self):
        st, _, body, _ = self.app.handle("POST", "/api/engagement", {}, b"{not json")
        self.assertEqual(st, 400)
        self.assertIn("invalid JSON", json.loads(body)["error"])

    def test_create_defaults_to_director_engine(self):
        self._post("/api/engagement", {"engagement": "d1", "mode": "semi",
            "scope": {"domains": {"web": {"enabled": True, "in": ["acme.com"]}}}})
        cfg = json.loads(SQLiteStore(self.db).get_engagement("d1")["config"] or "{}")
        self.assertTrue(cfg.get("offensive_agent", {}).get("enabled"))

    def test_create_classic_engine_disables_agent(self):
        self._post("/api/engagement", {"engagement": "c1", "mode": "semi", "engine": "classic",
            "scope": {"domains": {"web": {"enabled": True, "in": ["acme.com"]}}}})
        cfg = json.loads(SQLiteStore(self.db).get_engagement("c1")["config"] or "{}")
        self.assertFalse(cfg.get("offensive_agent", {}).get("enabled"))

    def test_update_engagement_preserves_config(self):
        mk = {"engagement": "u1", "mode": "semi",
              "scope": {"domains": {"web": {"enabled": True, "in": ["a.com"]}}}}
        self.app.handle("POST", "/api/engagement", {}, json.dumps(mk).encode())
        # set OSINT context (a top-level config key) via CTF settings
        self.app.handle("POST", "/api/settings/ctf", {"eng": "u1"},
                        json.dumps({"osint_context": "keep me"}).encode())
        # re-save the SAME engagement through the create/update form
        self.app.handle("POST", "/api/engagement", {}, json.dumps(mk).encode())
        cfg = json.loads(SQLiteStore(self.db).get_engagement("u1")["config"])
        self.assertEqual(cfg.get("osint", {}).get("context"), "keep me")   # survived the re-save
        self.assertTrue(cfg["offensive_agent"]["enabled"])                 # engine still set

    def test_findings_expose_narrative_evidence(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                "e1.scope.json", "semi", {})
        store.upsert_finding("e1", {"title": "SQLi", "severity": "high",
            "source_tool": "agent-director",
            "evidence": {"description": "blind SQLi", "reproduction": "curl X",
                         "impact": "bypass", "remediation": "paramize"}})
        st, _, body, _ = self._get("/api/findings", eng="e1")
        row = json.loads(body)["findings"][0]
        self.assertEqual(row["evidence"]["reproduction"], "curl X")
        self.assertEqual(row["evidence"]["remediation"], "paramize")

    def test_finding_screenshot_slot_round_trips(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                "e1.scope.json", "semi", {})
        store.upsert_finding("e1", {"title": "X", "severity": "low", "evidence": {}})
        fid = store.list_findings("e1")[0]["id"]
        body = json.dumps({"findings": {str(fid): {"include": True, "screenshots": ["/tmp/a.png"]}}}).encode()
        st, _, _, _ = self.app.handle("POST", "/api/report-settings", {"eng": "e1"}, body)
        self.assertEqual(st, 200)
        st, _, gb, _ = self.app.handle("GET", "/api/report-settings", {"eng": "e1"}, b"")
        got = json.loads(gb)["findings"][str(fid)]["screenshots"]
        self.assertEqual(got, ["/tmp/a.png"])

    def test_scope_apply_writes_valid_scope(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["old.com"]},
                                "e1.scope.json", "semi", {})
        body = json.dumps({"scope": {"domains": {"web": {"enabled": True, "in": ["new.com"]}}}}).encode()
        st, _, _, _ = self.app.handle("POST", "/api/scope/apply", {"eng": "e1"}, body)
        self.assertEqual(st, 200)
        sc = json.loads(SQLiteStore(self.db).get_engagement("e1")["scope"])
        self.assertIn("new.com", sc.get("in_scope_domains", []))

    def test_scope_apply_rejects_empty_target(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["old.com"]},
                                "e1.scope.json", "semi", {})
        body = json.dumps({"scope": {"domains": {"web": {"enabled": True, "in": []}}}}).encode()
        st, _, _, _ = self.app.handle("POST", "/api/scope/apply", {"eng": "e1"}, body)
        self.assertEqual(st, 400)

    def test_scope_chat_returns_shape(self):
        store = SQLiteStore(self.db)
        store.create_engagement("e1", "E1", {"in_scope_domains": ["t.com"]},
                                "e1.scope.json", "semi", {})
        body = json.dumps({"typed_scope": {"in_scope_domains": ["t.com"]}, "messages": []}).encode()
        st, _, b, _ = self.app.handle("POST", "/api/scope/chat", {"eng": "e1"}, body)
        self.assertEqual(st, 200)
        d = json.loads(b)
        self.assertIn("reply", d)
        self.assertIn("proposed_scope", d)
