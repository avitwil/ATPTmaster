"""Report customization: include/exclude findings, operator notes, screenshots."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from atpt.state import SQLiteStore


def _build():
    p = Path("modules/report_ptes/module.py")
    spec = importlib.util.spec_from_file_location("report_ptes_c", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_report_md


class ReportCustomTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "atpt.db")
        self.store.create_engagement("e1", "E1", {"in_scope_domains": ["e1.com"]},
                                     "e1.scope.json", "semi", {})
        self.store.upsert_finding("e1", {"title": "SQLi in login", "severity": "high",
                                         "status": "validated", "domain": "Web"})
        self.store.upsert_finding("e1", {"title": "Verbose banner", "severity": "low",
                                         "status": "candidate", "domain": "Infra"})
        self.ids = [f["id"] for f in self.store.list_findings("e1")]
        self.build = _build()

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_includes_all(self):
        md = self.build(self.store, "e1", Path("."))
        self.assertIn("SQLi in login", md)
        self.assertIn("Verbose banner", md)

    def test_exclude_note_and_screenshot(self):
        keep, drop = self.ids[0], self.ids[1]
        self.store.update_engagement_config("e1", {"report": {"findings": {
            str(keep): {"include": True, "note": "Confirmed exploitable via sqlmap.",
                        "screenshots": ["/home/kali/shots/sqli.png"]},
            str(drop): {"include": False},
        }}})
        md = self.build(self.store, "e1", Path("."))
        self.assertIn("SQLi in login", md)
        self.assertNotIn("Verbose banner", md)                # excluded
        self.assertIn("Operator note:", md)
        self.assertIn("Confirmed exploitable via sqlmap.", md)
        self.assertIn("![screenshot](/home/kali/shots/sqli.png)", md)
