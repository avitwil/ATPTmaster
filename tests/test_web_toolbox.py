"""Operator-visible Toolbox endpoint — through WebApp._route (no sockets).

GET lists the learned skills (JSON files, no sqlite); DELETE removes one by
name. Mirrors the query convention already used elsewhere in web.py: by the
time a query dict reaches _route, values are scalars (the stdlib parser's
per-key list has already been flattened by the request handler), not lists.
"""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from atpt.web import WebApp
from atpt.toolbox import Toolbox


class WebToolboxTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.pd = Path(self._tmp.name)
        Toolbox(self.pd / "toolbox").save({
            "name": "ssh-brute", "applies_to": {"service_tags": ["ssh"]},
            "steps": [{"command": ["hydra", "{TARGET}"]}], "success_note": "brute"})
        self.app = WebApp(self.pd)

    def tearDown(self):
        self._tmp.cleanup()

    def test_get_lists_skills(self):
        status, ctype, body, _ = self.app._route("GET", "/api/toolbox", {}, None)
        self.assertEqual(status, 200)
        self.assertIn(b"ssh-brute", body)

    def test_delete_removes_skill(self):
        status, _, body, _ = self.app._route("DELETE", "/api/toolbox",
                                              {"name": "ssh-brute"}, None)
        self.assertEqual(status, 200)
        self.assertEqual(Toolbox(self.pd / "toolbox").list_skills(), [])


if __name__ == "__main__":
    unittest.main()
