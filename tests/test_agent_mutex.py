import json
import unittest

from atpt.config import offensive_agent_on


class MutexTest(unittest.TestCase):
    def test_flag_true(self):
        self.assertTrue(offensive_agent_on({"config": json.dumps({"offensive_agent": {"enabled": True}})}))

    def test_flag_absent(self):
        self.assertFalse(offensive_agent_on({"config": "{}"}))

    def test_bad_config(self):
        self.assertFalse(offensive_agent_on({"config": "not json"}))


if __name__ == "__main__":
    unittest.main()
