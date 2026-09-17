"""Global app_settings store + engagement config deep-merge."""
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore


class SettingsStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "atpt.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_settings_default_empty(self):
        self.assertEqual(self.store.get_settings(), {})

    def test_settings_roundtrip_and_merge(self):
        self.store.set_settings({"pentester_name": "Avi", "sudo_allowed": True})
        self.assertEqual(self.store.get_settings()["pentester_name"], "Avi")
        # merge: existing keys preserved, new keys added, given keys overwritten
        self.store.set_settings({"pentester_name": "Neo"})
        s = self.store.get_settings()
        self.assertEqual(s["pentester_name"], "Neo")
        self.assertTrue(s["sudo_allowed"])

    def test_settings_persist_across_connections(self):
        self.store.set_settings({"pentester_name": "Avi"})
        store2 = SQLiteStore(self.store.db_path)
        self.assertEqual(store2.get_settings()["pentester_name"], "Avi")

    def test_update_engagement_config_deep_merge(self):
        self.store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                     "e1.scope.json", "semi", {"rate": 150})
        self.store.update_engagement_config("e1", {"ctf": {"goals": "get root"}})
        self.store.update_engagement_config("e1", {"ctf": {"vpn_config_path": "/tmp/x.ovpn"}})
        import json
        cfg = json.loads(self.store.get_engagement("e1")["config"])
        self.assertEqual(cfg["rate"], 150)                       # untouched
        self.assertEqual(cfg["ctf"]["goals"], "get root")        # kept from first merge
        self.assertEqual(cfg["ctf"]["vpn_config_path"], "/tmp/x.ovpn")  # added by second
