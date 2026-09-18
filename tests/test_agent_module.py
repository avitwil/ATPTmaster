import json
import unittest
from pathlib import Path

from atpt.module import Manifest, RunContext
from modules.agent_offensive.module import AgentOffensive


def _mod():
    m = Manifest.from_file(Path("modules/agent_offensive/module.json"))
    return AgentOffensive(m, Path("."))


class _Store:
    def __init__(self):
        self.events = []

    def add_event(self, *a):
        self.events.append(a)


def _ctx(cfg, reasoner=None):
    eng = {"id": "e1", "config": json.dumps(cfg)}
    return RunContext(engagement=eng, scope={"in_scope_cidrs": ["10.1.1.0/24"]},
                      store=_Store(), project_dir=Path("."), reasoner=reasoner)


class ModuleTest(unittest.TestCase):
    def test_disabled_is_noop(self):
        res = _mod().run(_ctx({}))
        self.assertTrue(res.ok)
        self.assertEqual(res.assets, [])
        self.assertIn("disabled", res.summary)

    def test_manifest_is_intrusive_recon(self):
        m = Manifest.from_file(Path("modules/agent_offensive/module.json"))
        self.assertEqual(m.phase, "recon")
        self.assertTrue(m.intrusive)

    def test_enabled_drives_loop(self):
        class R:  # fake reasoner: one in-scope nmap then done
            def __init__(self):
                self.it = iter(['{"command":["nmap","-Pn","10.1.1.5"]}', '{"done":true}'])

            def reason(self, prompt, phase):
                class Res:
                    text = next(self.it)
                return Res()

        import modules.agent_offensive.module as M
        M.execute = lambda argv, timeout=300: {"rc": 0, "out": "22/tcp open ssh\n", "err": ""}
        try:
            res = _mod().run(_ctx({"offensive_agent": {"enabled": True, "max_steps": 5}}, reasoner=R()))
        finally:
            from modules.agent_offensive.executor import execute as real_execute
            M.execute = real_execute
        self.assertTrue(res.ok)
        self.assertTrue(any(a["asset_type"] == "service" for a in res.assets))


if __name__ == "__main__":
    unittest.main()
