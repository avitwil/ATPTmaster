import json
import os
import sys
import tempfile
import types
import unittest
from bench.actions import Action


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
    sys.modules["autopenbench"] = autopenbench_mod
    sys.modules["autopenbench.tools"] = tools
    sys.modules["autopenbench.shell"] = shell_mod


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


if __name__ == "__main__":
    unittest.main()
