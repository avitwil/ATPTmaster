import unittest

from modules.agent_offensive.guard import ScopeGuard, DEFAULT_ALLOW
from modules.agent_offensive.loop import run_loop

SCOPE = {"in_scope_cidrs": ["10.1.1.0/24"]}


def guard():
    return ScopeGuard(SCOPE, set(DEFAULT_ALLOW))


class LoopTest(unittest.TestCase):
    def test_block_then_alternative_runs(self):
        # step 1: out-of-scope (blocked, non-fatal) -> step 2: in-scope nmap
        scripted = iter([
            '{"command":["nmap","10.9.9.9"]}',
            '{"command":["nmap","-Pn","10.1.1.5"]}',
            '{"done": true}',
        ])
        events = []

        def rf(_):
            return next(scripted)

        def ex(argv, timeout=300):
            return {"rc": 0, "out": "22/tcp open ssh\n", "err": ""}

        def hv(argv, res):
            return ([{"value": "10.1.1.5:22/ssh", "asset_type": "service"}], [])

        assets, findings, summary = run_loop(
            goal="enumerate", guard=guard(), reason_fn=rf, max_steps=5,
            emit=lambda *a, **k: events.append(a), execute_fn=ex, harvest_fn=hv)
        self.assertEqual(len(assets), 1)
        self.assertTrue(any("block" in str(e).lower() for e in events))

    def test_failure_is_nonfatal(self):
        scripted = iter(['{"command":["nmap","-Pn","10.1.1.5"]}', '{"done":true}'])

        def ex(argv, timeout=300):
            return {"rc": -2, "out": "", "err": "boom"}

        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: next(scripted), max_steps=5,
            emit=lambda *a, **k: None, execute_fn=ex, harvest_fn=lambda a, r: ([], []))
        self.assertIn("done", summary.lower())

    def test_step_budget_stops(self):
        def ex(argv, timeout=300):
            return {"rc": 0, "out": "", "err": ""}

        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: '{"command":["nmap","-Pn","10.1.1.5"]}',
            max_steps=3, emit=lambda *a, **k: None, execute_fn=ex, harvest_fn=lambda a, r: ([], []))
        self.assertIn("budget", summary.lower())

    def test_halt_stops(self):
        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: '{"command":["nmap","-Pn","10.1.1.5"]}',
            max_steps=10, emit=lambda *a, **k: None,
            execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
            harvest_fn=lambda a, r: ([], []), halt_fn=lambda: True)
        self.assertIn("stopped", summary.lower())

    def test_no_reasoner_ends(self):
        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: None, max_steps=5,
            emit=lambda *a, **k: None, execute_fn=lambda *a, **k: {}, harvest_fn=lambda a, r: ([], []))
        self.assertIn("no_reasoner", summary)


if __name__ == "__main__":
    unittest.main()
