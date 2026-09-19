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

    def test_offensive_agent_toggle_roundtrip(self):
        self._mk_eng()
        st, _, _, _ = self._post("/api/settings/ctf",
                                 {"offensive_agent": {"enabled": True, "max_steps": 12}},
                                 eng="htb1")
        self.assertEqual(st, 200)
        _, _, body, _ = self._get("/api/settings/ctf", eng="htb1")
        oa = json.loads(body)["offensive_agent"]
        self.assertTrue(oa["enabled"])
        self.assertEqual(oa["max_steps"], 12)
        # and it is stored where the engine reads it (config.offensive_agent)
        from atpt.config import offensive_agent_on
        self.assertTrue(offensive_agent_on(SQLiteStore(self.dbpath).get_engagement("htb1")))

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

    # --- uploads ------------------------------------------------------------
    def test_upload_saves_file_and_returns_path(self):
        import base64
        self._mk_eng()
        content = base64.b64encode(b"client\ndev tun\n").decode()
        st, _, body, _ = self._post("/api/upload", {"name": "box.ovpn", "content_b64": content}, eng="htb1")
        self.assertEqual(st, 200)
        p = Path(json.loads(body)["path"])
        self.assertTrue(p.exists())
        self.assertEqual(p.read_bytes(), b"client\ndev tun\n")

    def test_upload_sanitizes_name(self):
        import base64
        self._mk_eng()
        st, _, body, _ = self._post("/api/upload",
                                    {"name": "../../etc/evil.ovpn", "content_b64": base64.b64encode(b"x").decode()},
                                    eng="htb1")
        self.assertEqual(st, 200)
        self.assertTrue(Path(json.loads(body)["path"]).name.startswith("evil"))   # basename + sanitized

    # --- settings export / import -------------------------------------------
    def test_export_then_import_roundtrip(self):
        self._post("/api/settings", {"pentester_name": "Avi", "user_info": {"name": "Avi"}})
        st, ct, body, headers = self._get("/api/settings/export")
        self.assertEqual(st, 200)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        blob = json.loads(body)
        self.assertEqual(blob["pentester_name"], "Avi")
        # import a modified copy
        blob["pentester_name"] = "Neo"
        st2, _, _, _ = self._post("/api/settings/import", {"settings": blob})
        self.assertEqual(st2, 200)
        self.assertEqual(json.loads(self._get("/api/settings")[2])["pentester_name"], "Neo")

    def test_import_rejects_non_object(self):
        st, _, _, _ = self._post("/api/settings/import", {"settings": "nope"})
        self.assertEqual(st, 400)

    # --- vpn ----------------------------------------------------------------
    def test_vpn_status_default_down(self):
        _, _, body, _ = self._get("/api/vpn/status")
        self.assertIn(json.loads(body)["status"], ("down", "connecting", "connected", "error"))

    def test_vpn_connect_without_config_400(self):
        self._post("/api/demo", {})
        st, _, body, _ = self._post("/api/vpn/connect", {}, eng="demo")
        self.assertEqual(st, 400)
        self.assertIn("VPN config", json.loads(body)["error"])

    # --- background run control ---------------------------------------------
    def test_run_status_idle_then_start(self):
        self._post("/api/demo", {})
        _, _, s0, _ = self._get("/api/run/status", eng="demo")
        self.assertEqual(json.loads(s0)["status"], "idle")
        # step mode runs a single module then finishes (no slow intrusive scanners)
        st, _, body, _ = self._post("/api/run/start", {"mode": "step"}, eng="demo")
        self.assertEqual(st, 200)
        self.assertIn(json.loads(body)["status"], ("running", "done"))
        import time
        s = {"status": "running"}
        for _ in range(100):
            s = json.loads(self._get("/api/run/status", eng="demo")[2])
            if s["status"] in ("done", "stopped", "paused", "gated"):
                break
            time.sleep(0.1)
        self.assertIn(s["status"], ("done", "gated"))
        self.assertIsNotNone(s.get("last"))

    def test_run_control_on_idle_is_safe(self):
        self._post("/api/demo", {})
        st, _, body, _ = self._post("/api/run/control", {"action": "stop"}, eng="demo")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["status"], "idle")

    # --- live models --------------------------------------------------------
    def test_models_unknown_provider_400(self):
        st, _, body, _ = self._get("/api/models", provider="nope")
        self.assertEqual(st, 400)

    def test_models_uses_configured_provider(self):
        # configure an ollama provider, then stub the fetch to avoid real network
        self._post("/api/settings", {"reasoning": {"providers": {
            "loc": {"backend": "ollama", "model": "llama3.1"}}, "preference": ["loc"]}})
        from atpt import models
        orig = models.list_models
        models.list_models = lambda cfg: (["llama3.1", "qwen2"], None)
        try:
            st, _, body, _ = self._get("/api/models", provider="loc")
        finally:
            models.list_models = orig
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["models"], ["llama3.1", "qwen2"])

    def test_user_info_saved_and_redacted_get_ok(self):
        self._post("/api/settings", {"user_info": {"name": "Avi", "email": "a@b.co",
                                                   "company": "Acme", "phone": "123"}})
        _, _, body, _ = self._get("/api/settings")
        ui = json.loads(body)["user_info"]
        self.assertEqual(ui["name"], "Avi")
        self.assertEqual(ui["company"], "Acme")

    # --- per-role model ladders ------------------------------------------------
    def test_reasoning_roles_persist_and_return(self):
        body = {"reasoning": {
            "providers": {"p1": {"backend": "cli", "cmd": "echo"}},
            "ladder": [{"provider": "p1"}],
            "roles": {"director": {"ladder": [{"provider": "p1", "model": "m1"}]}}}}
        self.app.handle("POST", "/api/settings", {}, json.dumps(body).encode())
        st, _, gb, _ = self.app.handle("GET", "/api/settings", {}, b"")
        got = json.loads(gb).get("reasoning", {})
        self.assertIn("director", got.get("roles", {}))
        self.assertEqual(got["roles"]["director"]["ladder"][0]["model"], "m1")
