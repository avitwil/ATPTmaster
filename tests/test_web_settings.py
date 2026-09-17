"""Settings/CTF/provider web endpoints — through WebApp.handle (no sockets).

Security-critical assertions: API keys are redacted on GET; the sudo and
attack-box SSH passwords are NEVER written to the database and have no GET.
"""
import json
import tempfile
import unittest
from pathlib import Path

from atpt import privilege
from atpt.state import SQLiteStore
from atpt.web import WebApp


class WebSettingsTest(unittest.TestCase):
    def setUp(self):
        privilege.reset()
        self.tmp = tempfile.TemporaryDirectory()
        self.dbpath = Path(self.tmp.name) / "atpt.db"
        self.app = WebApp(".", db_path=self.dbpath)

    def tearDown(self):
        privilege.reset()
        self.tmp.cleanup()

    def _get(self, path, **q):
        return self.app.handle("GET", path, {k: str(v) for k, v in q.items()}, b"")

    def _post(self, path, obj, **q):
        return self.app.handle("POST", path, {k: str(v) for k, v in q.items()},
                               json.dumps(obj).encode())

    # --- global settings -----------------------------------------------------
    def test_settings_roundtrip(self):
        st, _, _, _ = self._post("/api/settings", {"pentester_name": "Avi"})
        self.assertEqual(st, 200)
        _, _, body, _ = self._get("/api/settings")
        self.assertEqual(json.loads(body)["pentester_name"], "Avi")

    def test_api_key_redacted_on_get_but_preserved(self):
        self._post("/api/settings", {"reasoning": {
            "providers": {"p1": {"backend": "http_api", "api": "openai",
                                 "model": "gpt-x", "api_key": "sk-secret"}},
            "preference": ["p1"]}})
        _, _, body, _ = self._get("/api/settings")
        prov = json.loads(body)["reasoning"]["providers"]["p1"]
        self.assertNotIn("api_key", prov)          # never leaked
        self.assertTrue(prov["has_key"])           # presence flagged
        # posting again with no key must PRESERVE the stored one
        self._post("/api/settings", {"reasoning": {
            "providers": {"p1": {"backend": "http_api", "api": "openai", "model": "gpt-x"}},
            "preference": ["p1"]}})
        raw = SQLiteStore(self.dbpath).get_settings()
        self.assertEqual(raw["reasoning"]["providers"]["p1"]["api_key"], "sk-secret")

    def test_env_var_key_mode_stores_no_secret(self):
        self._post("/api/settings", {"reasoning": {
            "providers": {"p2": {"backend": "http_api", "api": "anthropic",
                                 "model": "claude-x", "key_env": "ANTHROPIC_API_KEY"}},
            "preference": ["p2"]}})
        raw = SQLiteStore(self.dbpath).get_settings()
        self.assertNotIn("api_key", raw["reasoning"]["providers"]["p2"])
        self.assertEqual(raw["reasoning"]["providers"]["p2"]["key_env"], "ANTHROPIC_API_KEY")

    def test_sudo_allowed_toggles_privilege(self):
        self._post("/api/settings", {"sudo_allowed": True})
        self.assertTrue(privilege.is_allowed())
        self._post("/api/settings", {"sudo_allowed": False})
        self.assertFalse(privilege.is_allowed())

    # --- sudo password (memory only) ----------------------------------------
    def test_sudo_password_never_touches_db_and_has_no_get(self):
        self._post("/api/settings", {"sudo_allowed": True})
        st, _, _, _ = self._post("/api/settings/sudo-password", {"password": "r00tme"})
        self.assertEqual(st, 200)
        self.assertTrue(privilege.has_password())
        # not in the DB anywhere
        blob = Path(self.dbpath).read_bytes()
        self.assertNotIn(b"r00tme", blob)
        # no GET route for it
        st2, _, _, _ = self._get("/api/settings/sudo-password")
        self.assertIn(st2, (404, 405))

    # --- CTF (per engagement) ------------------------------------------------
    def _mk_eng(self):
        self._post("/api/engagement", {"engagement": "htb1", "name": "HTB box",
                                       "scope": {"in_scope_domains": ["10.10.10.10"]}})

    def test_ctf_roundtrip(self):
        self._mk_eng()
        st, _, _, _ = self._post("/api/settings/ctf",
                                 {"goals": "get user+root flags", "vpn_config_path": "/tmp/a.ovpn"},
                                 eng="htb1")
        self.assertEqual(st, 200)
        _, _, body, _ = self._get("/api/settings/ctf", eng="htb1")
        ctf = json.loads(body)
        self.assertEqual(ctf["goals"], "get user+root flags")
        self.assertEqual(ctf["vpn_config_path"], "/tmp/a.ovpn")

    def test_ctf_attackbox_password_not_persisted(self):
        self._mk_eng()
        self._post("/api/settings/ctf",
                   {"attackbox": {"host": "10.10.14.1", "user": "kali", "password": "kalikali"}},
                   eng="htb1")
        blob = Path(self.dbpath).read_bytes()
        self.assertNotIn(b"kalikali", blob)              # password kept in memory only
        self.assertTrue(privilege.has_attackbox_password("htb1"))
        raw = SQLiteStore(self.dbpath).get_engagement("htb1")
        cfg = json.loads(raw["config"])
        self.assertEqual(cfg["ctf"]["attackbox"]["host"], "10.10.14.1")   # host IS stored
        self.assertNotIn("password", cfg["ctf"]["attackbox"])

    def test_ctf_attackbox_requires_host_and_user(self):
        self._mk_eng()
        st, _, body, _ = self._post("/api/settings/ctf",
                                    {"attackbox": {"host": "", "user": "kali"}}, eng="htb1")
        self.assertEqual(st, 400)

    # --- providers -----------------------------------------------------------
    def test_provider_status_lists_registry(self):
        _, _, body, _ = self._get("/api/providers/status")
        data = json.loads(body)
        names = {p["name"] for p in data["providers"]}
        self.assertTrue({"claude", "gemini", "codex"}.issubset(names))

    def test_provider_install_unknown_errors(self):
        st, _, body, _ = self._post("/api/providers/install", {"name": "totally-unknown"})
        self.assertEqual(st, 400)

    # --- app mode ------------------------------------------------------------
    def test_mode_endpoint_sets_engagement_mode(self):
        self._mk_eng()
        st, _, _, _ = self._post("/api/mode", {"mode": "full"}, eng="htb1")
        self.assertEqual(st, 200)
        self.assertEqual(SQLiteStore(self.dbpath).get_engagement("htb1")["mode"], "full")

    def test_mode_endpoint_rejects_bad_mode(self):
        self._mk_eng()
        st, _, _, _ = self._post("/api/mode", {"mode": "yolo"}, eng="htb1")
        self.assertEqual(st, 400)

    def test_user_info_saved_and_redacted_get_ok(self):
        self._post("/api/settings", {"user_info": {"name": "Avi", "email": "a@b.co",
                                                   "company": "Acme", "phone": "123"}})
        _, _, body, _ = self._get("/api/settings")
        ui = json.loads(body)["user_info"]
        self.assertEqual(ui["name"], "Avi")
        self.assertEqual(ui["company"], "Acme")
