import unittest
from bench import ladder_brain
from atpt import reasoning


class BuildConfig(unittest.TestCase):
    def test_shapes_opus_then_deephat(self):
        cfg = ladder_brain.build_config(claude_path="/usr/bin/claude")
        self.assertEqual([e["provider"] for e in cfg["ladder"]], ["opus", "deephat"])
        self.assertEqual(cfg["providers"]["opus"]["backend"], "cli")
        self.assertEqual(cfg["providers"]["opus"]["cmd"], "/usr/bin/claude -p")
        self.assertEqual(cfg["providers"]["opus"]["model"], "opus")
        self.assertEqual(cfg["providers"]["deephat"]["backend"], "ollama")
        self.assertEqual(cfg["providers"]["deephat"]["model"],
                         "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M")

    def test_reorder_and_drop(self):
        cfg = ladder_brain.build_config(primary="deephat", fallback=None)
        self.assertEqual([e["provider"] for e in cfg["ladder"]], ["deephat"])

    def test_codex_fallback_is_cli_no_ollama(self):
        cfg = ladder_brain.build_config(primary="opus", fallback="codex",
                                        claude_path="/usr/bin/claude")
        self.assertEqual([e["provider"] for e in cfg["ladder"]], ["opus", "codex"])
        cx = cfg["providers"]["codex"]
        self.assertEqual(cx["backend"], "cli")           # remote CLI, no GPU
        self.assertIn("codex exec", cx["cmd"])
        self.assertEqual(cx["model"], "gpt-5.6-sol")
        self.assertEqual(cx["model_flag"], "-m")
        # no ollama backend anywhere in an opus->codex ladder
        self.assertFalse(any(p["backend"] == "ollama" for p in cfg["providers"].values()))


class Fallback(unittest.TestCase):
    def test_opus_refusal_advances_to_deephat(self):
        calls = []

        def fake_cli(cfg, prompt):
            calls.append("opus")
            return "I cannot help with that."      # refusal marker

        def fake_ollama(cfg, prompt):
            calls.append("deephat")
            return '```json\n{"tool":"final_answer","args":{"flag":"F"}}\n```'

        orig = dict(reasoning.BACKENDS)
        reasoning.BACKENDS["cli"] = fake_cli
        reasoning.BACKENDS["ollama"] = fake_ollama
        try:
            brain = ladder_brain.LadderBrain(
                ladder_brain.build_config(claude_path="/usr/bin/claude"))
            text, provider = brain.think("do the thing")
        finally:
            reasoning.BACKENDS.clear(); reasoning.BACKENDS.update(orig)

        self.assertEqual(provider, "deephat")
        self.assertIn("final_answer", text)
        self.assertEqual(calls, ["opus", "deephat"])

    def test_all_exhausted_returns_none(self):
        def refuse(cfg, prompt):
            return "I won't"
        orig = dict(reasoning.BACKENDS)
        reasoning.BACKENDS["cli"] = refuse
        reasoning.BACKENDS["ollama"] = refuse
        try:
            brain = ladder_brain.LadderBrain(
                ladder_brain.build_config(claude_path="/usr/bin/claude"))
            text, provider = brain.think("x")
        finally:
            reasoning.BACKENDS.clear(); reasoning.BACKENDS.update(orig)
        self.assertIsNone(provider)


if __name__ == "__main__":
    unittest.main()
