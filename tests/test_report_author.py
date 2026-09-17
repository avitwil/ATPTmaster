"""PTES report honors the operator's name from global settings."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore


def _build_report():
    p = Path("modules/report_ptes/module.py")
    spec = importlib.util.spec_from_file_location("report_ptes_t", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_report_md


class ReportAuthorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "atpt.db")
        self.store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                     "e1.scope.json", "semi", {})
        self.build = _build_report()

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_name_omits_prepared_by(self):
        md = self.build(self.store, "e1", Path("."))
        self.assertNotIn("Prepared by", md)

    def test_name_appears_in_report(self):
        self.store.set_settings({"pentester_name": "Avi Twil"})
        md = self.build(self.store, "e1", Path("."))
        self.assertIn("Prepared by:", md)
        self.assertIn("Avi Twil", md)

    def test_user_info_name_takes_precedence(self):
        self.store.set_settings({"pentester_name": "Old", "user_info": {"name": "New Name"}})
        md = self.build(self.store, "e1", Path("."))
        self.assertIn("New Name", md)
        self.assertNotIn("Prepared by: Old", md)
