"""Store read API for the full event transcript — used to reconstruct the run
transcript for the LLM-authored report (unlike recent_events, which caps at 15,
is DESC, and omits `data`)."""
import tempfile, unittest
from pathlib import Path
from atpt.state import SQLiteStore


class ListEventsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "db.sqlite")

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_events_all_in_order_with_data(self):
        for i in range(20):
            self.store.add_event("e1", "exploit", "agent", "info",
                                 "agent_step", f"step {i}", {"n": i})
        evs = self.store.list_events("e1")
        self.assertEqual(len(evs), 20)                     # not capped at 15
        self.assertEqual(evs[0]["message"], "step 0")      # ascending
        self.assertEqual(evs[-1]["message"], "step 19")
        self.assertIn("data", evs[0])                      # includes data column
