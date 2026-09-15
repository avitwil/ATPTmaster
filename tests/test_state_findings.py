"""Store read/mutate APIs for findings — consumed by validate + report modules."""
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore


class FindingStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")
        self.store.create_engagement("E", "E", {}, "s.json", "full", {})

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_findings_returns_rows_with_id(self):
        self.store.upsert_finding("E", {"title": "t1", "severity": "high"})
        rows = self.store.list_findings("E")
        self.assertEqual(len(rows), 1)
        self.assertIn("id", rows[0])
        self.assertEqual(rows[0]["status"], "candidate")

    def test_list_findings_filters_by_status(self):
        self.store.upsert_finding("E", {"title": "a", "status": "candidate"})
        self.store.upsert_finding("E", {"title": "b", "status": "validated"})
        vals = [f["title"] for f in self.store.list_findings("E", status="validated")]
        self.assertEqual(vals, ["b"])

    def test_set_finding_status_promotes(self):
        self.store.upsert_finding("E", {"title": "t", "status": "candidate"})
        fid = self.store.list_findings("E")[0]["id"]
        self.store.set_finding_status("E", fid, "validated")
        self.assertEqual(self.store.count_findings("E", status="validated"), 1)

    def test_set_finding_status_scoped_to_engagement(self):
        self.store.create_engagement("F", "F", {}, "s.json", "full", {})
        self.store.upsert_finding("E", {"title": "t"})
        fid = self.store.list_findings("E")[0]["id"]
        # attempting to promote under the wrong engagement must not change E's finding
        self.store.set_finding_status("F", fid, "validated")
        self.assertEqual(self.store.count_findings("E", status="validated"), 0)
