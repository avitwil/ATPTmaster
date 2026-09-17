"""Self-update: repo detection, and update endpoints (git calls stubbed)."""
import json
import tempfile
import unittest
from pathlib import Path

from atpt import selfupdate
from atpt.web import WebApp


class SelfUpdateTest(unittest.TestCase):
    def test_non_repo_reports_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(selfupdate.check(d)["repo"])
            self.assertFalse(selfupdate.apply(d)["ok"])

    def test_repo_check_has_shape(self):
        # the project itself is a git checkout; don't assert on network results
        r = selfupdate.check(".")
        self.assertTrue(r["repo"])
        self.assertTrue("current" in r or "error" in r)


class UpdateEndpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = WebApp(".", db_path=Path(self.tmp.name) / "atpt.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_update_check_endpoint(self):
        orig = selfupdate.check
        selfupdate.check = lambda pd: {"repo": True, "branch": "main", "current": "abc1234",
                                       "latest": "def5678", "behind": 1,
                                       "changelog": ["def5678 feat: x (a, 1h ago)"]}
        try:
            st, _, body, _ = self.app.handle("GET", "/api/update/check", {}, b"")
        finally:
            selfupdate.check = orig
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["behind"], 1)

    def test_update_apply_endpoint(self):
        orig = selfupdate.apply
        selfupdate.apply = lambda pd: {"ok": True, "output": "Updating abc..def\nFast-forward"}
        try:
            st, _, body, _ = self.app.handle("POST", "/api/update/apply", {}, b"{}")
        finally:
            selfupdate.apply = orig
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["ok"])
