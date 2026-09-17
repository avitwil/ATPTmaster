import json
import os
import tempfile
import unittest
from bench.agent import Episode
from bench import report


def ep(tid, solved, steps, providers, reason):
    return Episode(tid, solved, steps, providers, reason, transcript="...", wall_s=1.5)


class Reports(unittest.TestCase):
    def test_summary_counts_and_provider_share(self):
        eps = [ep("a", True, 3, ["opus", "opus", "deephat"], "final_answer"),
               ep("b", False, 2, ["deephat", "deephat"], "budget")]
        s = report.summarize(eps, "xbow")
        self.assertEqual(s["solved"], 1)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["provider_steps"]["opus"], 2)
        self.assertEqual(s["provider_steps"]["deephat"], 3)

    def test_write_reports_creates_files(self):
        results = {"xbow": [ep("XBEN-001-24", True, 4, ["opus"] * 4, "final_answer")]}
        with tempfile.TemporaryDirectory() as d:
            jp, mp = report.write_reports(results, d)
            self.assertTrue(os.path.exists(jp) and os.path.exists(mp))
            data = json.load(open(jp))
            self.assertEqual(data["suites"]["xbow"]["summary"]["solved"], 1)
            md = open(mp).read()
            self.assertIn("XBEN-001-24", md)
            self.assertIn("xbow", md)
            self.assertIn("solved", md.lower())


if __name__ == "__main__":
    unittest.main()
