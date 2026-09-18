import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from atpt.toolbox import Toolbox, slugify, goal_tags, service_tags_from_assets


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


class ToolboxRetrievalTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tb = Toolbox(Path(self._tmp.name) / "toolbox")

    def tearDown(self):
        self._tmp.cleanup()

    def test_goal_tags_drops_generic_and_short(self):
        self.assertEqual(goal_tags("Capture the flags on the box"), [])
        tags = goal_tags("Exploit the Wordpress login")
        self.assertIn("wordpress", tags)
        self.assertIn("login", tags)
        self.assertNotIn("the", tags)

    def test_service_tags_from_assets(self):
        assets = [{"asset_type": "service", "service": "ssh"},
                  {"asset_type": "service", "service": "http", "product": "Apache httpd"},
                  {"asset_type": "web_endpoint", "url": "http://h/"}]
        tags = service_tags_from_assets(assets)
        self.assertIn("ssh", tags)
        self.assertIn("http", tags)
        self.assertIn("apache", tags)

    def test_search_ranks_service_overlap_highest(self):
        self.tb.save({"name": "http-sqli", "applies_to": {"goal_tags": [],
                     "service_tags": ["http", "mysql"]},
                     "steps": [{"command": ["sqlmap", "-u", "{TARGET_URL}"]}], "success_note": "a"})
        self.tb.save({"name": "ssh-brute", "applies_to": {"goal_tags": ["login"],
                     "service_tags": ["ssh"]},
                     "steps": [{"command": ["hydra", "{TARGET}"]}], "success_note": "b"})
        hits = self.tb.search(goal_tags_q=["login"], service_tags_q=["http", "mysql"], limit=2)
        self.assertEqual(hits[0]["name"], "http-sqli")   # 2*2 > 1 (goal 'login')

    def test_search_returns_nothing_on_no_overlap(self):
        self.tb.save({"name": "ssh-brute", "applies_to": {"service_tags": ["ssh"]},
                      "steps": [{"command": ["hydra", "{TARGET}"]}]})
        self.assertEqual(self.tb.search([], ["smb"]), [])
