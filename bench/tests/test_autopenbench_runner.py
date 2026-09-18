import json
import os
import sys
import tempfile
import types
import unittest
from bench.actions import Action


_APB_CALLS = {"load_milestones": 0}


def _install_fake_apb():
    """Register minimal fake autopenbench.* modules before importing the runner."""
    tools = types.ModuleType("autopenbench.tools")

    class _Tool:
        def __init__(self, **kw): self.kw = kw
        def run(self, *a, **k): return f"ran:{self.kw}"

    class ExecuteBash(_Tool): pass
    class SSHConnect(_Tool):
        def run(self, *a, **k): return ("channel", "ssh-ok")
    class WriteFile(_Tool):
        def run(self, *a, **k): return "wrote"
    class FinalAnswer(_Tool): pass
    tools.ExecuteBash, tools.SSHConnect = ExecuteBash, SSHConnect
    tools.WriteFile, tools.FinalAnswer = WriteFile, FinalAnswer
    autopenbench_mod = types.ModuleType("autopenbench")
    shell_mod = types.ModuleType("autopenbench.shell")
    shell_mod.RemoteShell = lambda ch: ("remote", ch)
    utils_mod = types.ModuleType("autopenbench.utils")

    def _load_milestones(*a, **k):
        _APB_CALLS["load_milestones"] += 1     # records if the judge path runs
        return []
    utils_mod.load_milestones = _load_milestones
    sys.modules["autopenbench"] = autopenbench_mod
    sys.modules["autopenbench.tools"] = tools
    sys.modules["autopenbench.shell"] = shell_mod
    sys.modules["autopenbench.utils"] = utils_mod


class LoadTasks(unittest.TestCase):
    def test_first_n_in_vitro(self):
        _install_fake_apb()
        from bench import autopenbench_runner as A
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "data"))
            games = {"in-vitro": {"access_control": [
                        {"task": "t0", "flag": "F0", "target": "vm0", "vulnerability": "x"}],
                     "web_security": [
                        {"task": "t1", "flag": "F1", "target": "vm1", "vulnerability": "y"}]},
                     "real-world": {}}
            json.dump(games, open(os.path.join(root, "data/games.json"), "w"))
            tasks = A.load_tasks(root, limit=2)
            self.assertEqual(len(tasks), 2)
            self.assertEqual(tasks[0]["category"], "access_control")
            self.assertEqual(tasks[0]["flag"], "F0")


class ExecutorMapping(unittest.TestCase):
    def test_final_answer_scores_exact_flag(self):
        _install_fake_apb()
        from bench import autopenbench_runner as A

        class FakeDriver:
            remotes = {"192.168.0.5": object()}
        ex = A.APBExecutor(FakeDriver(), flag="SECRET")
        good = ex.run(Action("", "final_answer", {"flag": "SECRET"}))
        bad = ex.run(Action("", "final_answer", {"flag": "no"}))
        self.assertTrue(good.done and good.success)
        self.assertTrue(bad.done and not bad.success)

    def test_execute_bash_runs_apb_tool(self):
        _install_fake_apb()
        from bench import autopenbench_runner as A

        class FakeDriver:
            remotes = {"192.168.0.5": "SHELL"}
        ex = A.APBExecutor(FakeDriver(), flag="F")
        obs = ex.run(Action("", "execute_bash",
                            {"machine_ipaddr": "192.168.0.5", "cmd": "id"}))
        self.assertIn("ran:", obs.text)
        self.assertFalse(obs.done)


class CleanObservation(unittest.TestCase):
    def test_strips_ansi_and_bracketed_paste(self):
        _install_fake_apb()
        from bench import autopenbench_runner as A
        raw = "\x1b[?2004l\x1b[36mlo\x1b[0m  UP 192.168.0.5\x1b[?2004h\r\nroot@kali:~# "
        out = A._clean_obs(raw)
        self.assertNotIn("\x1b", out)          # no escape sequences remain
        self.assertNotIn("[?2004", out)        # bracketed-paste markers gone
        self.assertIn("lo", out)               # real content preserved
        self.assertIn("UP 192.168.0.5", out)

    def test_none_safe(self):
        _install_fake_apb()
        from bench import autopenbench_runner as A
        self.assertEqual(A._clean_obs(None), "")


class MilestoneJudgeOptIn(unittest.TestCase):
    def test_default_skips_local_judge_no_ollama(self):
        _install_fake_apb()
        _APB_CALLS["load_milestones"] = 0
        from bench import autopenbench_runner as A

        class FakeDriver:
            def __init__(self, *a):
                self.remotes = {"192.168.0.5": "S"}
                self.ssh_kali = None

            def reset(self):
                return (None, False)

        class Brain:
            def think(self, transcript):
                return '```json\n{"tool":"final_answer","args":{"flag":"F"}}\n```', "opus"

        eps = A.run_suite(
            [{"task": "t", "flag": "F", "target": "vm0",
              "category": "access_control", "idx": 0}],
            Brain(), driver_factory=FakeDriver, max_steps=3)   # no evaluator_factory
        self.assertEqual(len(eps), 1)
        self.assertTrue(eps[0].solved)                          # flag-match scoring works
        self.assertEqual(_APB_CALLS["load_milestones"], 0)      # judge NEVER invoked (no Ollama)


if __name__ == "__main__":
    unittest.main()
