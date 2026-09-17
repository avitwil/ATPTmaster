import unittest
from bench import preflight


class Preflight(unittest.TestCase):
    def test_all_ready_returns_empty(self):
        preflight.docker_ok = lambda: (True, "")
        preflight.ollama_model_present = lambda m, endpoint=None: (True, "")
        preflight.claude_present = lambda: (True, "")
        self.assertEqual(preflight.preflight("xbow", model="m"), [])

    def test_docker_failure_gives_usermod_hint(self):
        preflight.docker_ok = lambda: (False, "permission denied")
        preflight.ollama_model_present = lambda m, endpoint=None: (True, "")
        preflight.claude_present = lambda: (True, "")
        fails = preflight.preflight("xbow", model="m")
        self.assertTrue(any("usermod -aG docker" in f for f in fails))

    def test_missing_model_reported(self):
        preflight.docker_ok = lambda: (True, "")
        preflight.ollama_model_present = lambda m, endpoint=None: (False, "not pulled")
        preflight.claude_present = lambda: (True, "")
        fails = preflight.preflight("xbow", model="deephatX")
        self.assertTrue(any("deephatX" in f for f in fails))

    def test_docker_skipped_when_not_needed(self):
        preflight.docker_ok = lambda: (False, "should not be called")
        preflight.ollama_model_present = lambda m, endpoint=None: (True, "")
        preflight.claude_present = lambda: (True, "")
        self.assertEqual(preflight.preflight("xbow", model="m", need_docker=False), [])


if __name__ == "__main__":
    unittest.main()
