import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore


class ListAssetsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {}, "s.json", "full", {})

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_assets_returns_rows_with_id(self):
        self.store.upsert_asset("E", {"asset_type": "service", "value": "h1:22",
                                      "service": "ssh", "port": 22})
        rows = self.store.list_assets("E")
        self.assertEqual(len(rows), 1)
        self.assertIn("id", rows[0])
        self.assertIsInstance(rows[0]["id"], int)
        self.assertEqual(rows[0]["service"], "ssh")

    def test_list_assets_scoped_to_engagement(self):
        self.store.create_engagement("F", "F", {}, "s.json", "full", {})
        self.store.upsert_asset("E", {"asset_type": "host", "value": "a"})
        self.store.upsert_asset("F", {"asset_type": "host", "value": "b"})
        self.assertEqual([r["value"] for r in self.store.list_assets("E")], ["a"])
