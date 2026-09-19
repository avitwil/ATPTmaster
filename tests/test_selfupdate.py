"""Self-update: release (stable-tag) detection + update endpoints (git stubbed)."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from atpt import selfupdate
from atpt.web import WebApp


class _CP:
    """Stand-in for subprocess.CompletedProcess."""
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


_LS = ("aaa\trefs/tags/v1.0.0\n"
       "bbb\trefs/tags/v1.2.0\n"
       "ccc\trefs/tags/v1.10.0\n"          # numeric, not lexical, ordering
       "ddd\trefs/tags/v2.0.0-beta.1\n"    # pre-release -> must be skipped
       "eee\trefs/tags/v1.3.0-rc.2\n")     # pre-release -> must be skipped


class VersionLogicTest(unittest.TestCase):
    def test_semver_matches_stable_only(self):
        self.assertEqual(selfupdate._semver("v1.2.3"), (1, 2, 3))
        self.assertIsNone(selfupdate._semver("v1.2.3-beta.1"))
        self.assertIsNone(selfupdate._semver("nightly"))
        self.assertIsNone(selfupdate._semver(""))

    def test_remote_stable_tags_skips_prereleases_newest_first(self):
        with mock.patch.object(selfupdate, "_git", lambda *a, **k: _CP(_LS)):
            tags = selfupdate._remote_stable_tags(".")
        self.assertEqual(tags, ["v1.10.0", "v1.2.0", "v1.0.0"])   # betas gone, numeric sort


class CheckTest(unittest.TestCase):
    def _fake_git(self, describe):
        def g(args, cwd, timeout=90):
            head = args[0]
            if head == "describe":
                return _CP(describe)
            if head == "ls-remote":
                return _CP(_LS)
            if head == "log":
                return _CP("abc feat: something\ndef fix: other\n")
            return _CP("")
        return g

    def test_update_available_offers_latest_stable_not_beta(self):
        with mock.patch.object(selfupdate, "_is_repo", lambda p: True), \
             mock.patch.object(selfupdate, "_git", self._fake_git("v1.2.0")):
            r = selfupdate.check(".")
        self.assertTrue(r["update_available"])
        self.assertEqual(r["latest"], "v1.10.0")     # stable, not the v2.0.0-beta.1
        self.assertEqual(r["current"], "v1.2.0")
        self.assertTrue(r["changelog"])

    def test_up_to_date_on_latest_stable(self):
        with mock.patch.object(selfupdate, "_is_repo", lambda p: True), \
             mock.patch.object(selfupdate, "_git", self._fake_git("v1.10.0")):
            r = selfupdate.check(".")
        self.assertFalse(r["update_available"])

    def test_no_stable_release_is_a_note_not_an_error(self):
        def g(args, cwd, timeout=90):
            return _CP("")                     # ls-remote yields nothing, describe empty
        with mock.patch.object(selfupdate, "_is_repo", lambda p: True), \
             mock.patch.object(selfupdate, "_git", g):
            r = selfupdate.check(".")
        self.assertFalse(r["update_available"])
        self.assertNotIn("error", r)
        self.assertIn("note", r)

    def test_non_repo_reports_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(selfupdate.check(d)["repo"])
            self.assertFalse(selfupdate.apply(d)["ok"])


class ApplyTest(unittest.TestCase):
    def test_apply_backs_up_then_resets_to_latest_stable(self):
        calls = []

        def g(args, cwd, timeout=90):
            calls.append(list(args))
            if args[0] == "ls-remote":
                return _CP(_LS)
            if args[0] == "rev-parse":
                return _CP("deadbee")
            return _CP("")

        with mock.patch.object(selfupdate, "_is_repo", lambda p: True), \
             mock.patch.object(selfupdate, "_git", g):
            r = selfupdate.apply(".")
        self.assertTrue(r["ok"])
        self.assertEqual(r["tag"], "v1.10.0")                     # the stable tag, not the beta
        self.assertIn(["reset", "--hard", "v1.10.0"], calls)
        # a data-safe backup stash runs BEFORE the reset (never blocks a dirty tree)
        stash_i = next(i for i, a in enumerate(calls) if a[:2] == ["stash", "push"])
        reset_i = next(i for i, a in enumerate(calls) if a[:2] == ["reset", "--hard"])
        self.assertLess(stash_i, reset_i)


class UpdateEndpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = WebApp(".", db_path=Path(self.tmp.name) / "atpt.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_update_check_endpoint(self):
        orig = selfupdate.check
        selfupdate.check = lambda pd: {"repo": True, "current": "v1.0.0", "latest": "v1.2.0",
                                       "update_available": True,
                                       "changelog": ["abc feat: x"]}
        try:
            st, _, body, _ = self.app.handle("GET", "/api/update/check", {}, b"")
        finally:
            selfupdate.check = orig
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["update_available"])

    def test_update_apply_endpoint(self):
        orig = selfupdate.apply
        selfupdate.apply = lambda pd: {"ok": True, "tag": "v1.2.0", "head": "deadbee",
                                       "output": "HEAD is now at deadbee"}
        try:
            st, _, body, _ = self.app.handle("POST", "/api/update/apply", {}, b"{}")
        finally:
            selfupdate.apply = orig
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["ok"])


if __name__ == "__main__":
    unittest.main()
