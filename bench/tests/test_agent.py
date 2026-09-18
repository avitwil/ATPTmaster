import unittest
from bench.actions import Action
from bench.agent import Observation, run_episode


class FakeBrain:
    """Yields scripted model outputs; records the provider that 'answered'."""
    def __init__(self, outputs, provider="opus"):
        self.outputs = list(outputs)
        self.provider = provider
        self.seen = []

    def think(self, transcript):
        self.seen.append(transcript)
        if not self.outputs:
            return "", None
        return self.outputs.pop(0), self.provider


class FakeExecutor:
    def __init__(self):
        self.ran = []

    def tools(self):
        return [{"name": "execute_bash", "args": ["cmd"], "desc": "run"},
                {"name": "final_answer", "args": ["flag"], "desc": "submit"}]

    def system_preamble(self):
        return "You are a pentest agent."

    def run(self, action: Action):
        self.ran.append(action)
        if action.tool == "final_answer":
            return Observation(text="checked", done=True,
                               success=action.args.get("flag") == "GOOD")
        return Observation(text=f"ran {action.args.get('cmd')}")


class EpisodeLoop(unittest.TestCase):
    def test_solves_and_records_provider(self):
        brain = FakeBrain([
            '```json\n{"tool":"execute_bash","args":{"cmd":"ls"}}\n```',
            '```json\n{"tool":"final_answer","args":{"flag":"GOOD"}}\n```',
        ])
        ex = FakeExecutor()
        ep = run_episode(brain, ex, "t1", "find the flag", max_steps=10)
        self.assertTrue(ep.solved)
        self.assertEqual(ep.steps, 2)
        self.assertEqual(ep.providers, ["opus", "opus"])
        self.assertEqual(ep.stop_reason, "final_answer")

    def test_budget_stop(self):
        brain = FakeBrain(['```json\n{"tool":"execute_bash","args":{"cmd":"x"}}\n```'] * 50)
        ep = run_episode(brain, FakeExecutor(), "t2", "goal", max_steps=3)
        self.assertFalse(ep.solved)
        self.assertEqual(ep.steps, 3)
        self.assertEqual(ep.stop_reason, "budget")

    def test_malformed_reprompt_then_recover(self):
        brain = FakeBrain([
            "I will not emit json",                                        # malformed 1
            '```json\n{"tool":"final_answer","args":{"flag":"GOOD"}}\n```',# recover
        ])
        ep = run_episode(brain, FakeExecutor(), "t3", "goal", max_steps=10)
        self.assertTrue(ep.solved)
        self.assertEqual(ep.stop_reason, "final_answer")

    def test_two_malformed_stops(self):
        brain = FakeBrain(["nope", "still nope", "third"])
        ep = run_episode(brain, FakeExecutor(), "t4", "goal", max_steps=10)
        self.assertFalse(ep.solved)
        self.assertEqual(ep.stop_reason, "malformed")

    def test_no_reasoner_stops(self):
        brain = FakeBrain([], provider="opus")   # empty -> (text="", None)
        ep = run_episode(brain, FakeExecutor(), "t5", "goal", max_steps=10)
        self.assertFalse(ep.solved)
        self.assertEqual(ep.stop_reason, "no_reasoner")

    def test_transient_reasoner_failure_is_retried(self):
        class FlakyBrain:
            def __init__(self):
                self.calls = 0

            def think(self, transcript):
                self.calls += 1
                if self.calls == 1:            # first think fails (e.g. timeout)
                    return "", None
                return '```json\n{"tool":"final_answer","args":{"flag":"GOOD"}}\n```', "opus"

        ep = run_episode(FlakyBrain(), FakeExecutor(), "t8", "goal", max_steps=5)
        self.assertTrue(ep.solved)             # recovered instead of no_reasoner
        self.assertEqual(ep.stop_reason, "final_answer")

    def test_tool_error_becomes_observation_and_continues(self):
        calls = {"n": 0}

        class RaisingExecutor(FakeExecutor):
            def run(self, action):
                if action.tool == "execute_bash":
                    calls["n"] += 1
                    raise RuntimeError("boom")
                return super().run(action)

        brain = FakeBrain([
            '```json\n{"tool":"execute_bash","args":{"cmd":"x"}}\n```',   # raises
            '```json\n{"tool":"final_answer","args":{"flag":"GOOD"}}\n```',
        ])
        ep = run_episode(brain, RaisingExecutor(), "t6", "goal", max_steps=10)
        self.assertTrue(ep.solved)                 # tool error was non-fatal
        self.assertEqual(ep.stop_reason, "final_answer")
        self.assertEqual(ep.steps, 2)              # error step counted, loop continued
        self.assertEqual(calls["n"], 1)


if __name__ == "__main__":
    unittest.main()
