import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from atpt.toolbox import Toolbox, slugify


class ToolboxStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name) / "toolbox"
        self.tb = Toolbox(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _skill(self, name="SQLi UNION dump", svc=("http", "mysql")):
        return {"name": name,
                "applies_to": {"goal_tags": ["dump", "db"], "service_tags": list(svc)},
                "steps": [{"command": ["sqlmap", "-u", "{TARGET_URL}", "--batch", "--dump"],
                           "note": "id param"}],
                "success_note": "UNION SQLi dumped users"}

    def test_slugify(self):
        self.assertEqual(slugify("SQLi UNION dump"), "sqli-union-dump")
        self.assertEqual(slugify("  weird__Name!! "), "weird-name")
        self.assertEqual(slugify(""), "skill")

    def test_save_writes_file_and_returns_path(self):
        p = self.tb.save(self._skill())
        self.assertTrue(p.exists())
        self.assertEqual(p.name, "sqli-union-dump.json")
        rec = json.loads(p.read_text())
        self.assertEqual(rec["applies_to"]["service_tags"], ["http", "mysql"])
        self.assertIn("updated_at", rec)

    def test_save_rejects_nameless_or_stepless(self):
        self.assertIsNone(self.tb.save({"name": "", "steps": [{"command": ["x"]}]}))
        self.assertIsNone(self.tb.save({"name": "x", "steps": []}))

    def test_list_and_get(self):
        self.tb.save(self._skill())
        self.assertEqual(len(self.tb.list_skills()), 1)
        self.assertEqual(self.tb.get("SQLi UNION dump")["success_note"], "UNION SQLi dumped users")
        self.assertIsNone(self.tb.get("nope"))

    def test_delete_removes_file(self):
        self.tb.save(self._skill())
        self.assertTrue(self.tb.delete("SQLi UNION dump"))
        self.assertFalse(self.tb.delete("SQLi UNION dump"))
        self.assertEqual(self.tb.list_skills(), [])

    def test_reindex_picks_up_hand_dropped_file(self):
        # a shared skill dropped in by hand (not via save())
        (self.root).mkdir(parents=True, exist_ok=True)
        (self.root / "lfi-etc-passwd.json").write_text(json.dumps({
            "name": "lfi-etc-passwd",
            "applies_to": {"goal_tags": ["lfi"], "service_tags": ["http"]},
            "steps": [{"command": ["curl", "{TARGET_URL}/?p=../../etc/passwd"], "note": ""}],
            "success_note": "LFI"}))
        self.assertEqual(self.tb.reindex(), 1)
