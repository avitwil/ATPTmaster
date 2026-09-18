import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from modules.agent_offensive.guard import ScopeGuard, DEFAULT_ALLOW
from modules.agent_offensive.loop import run_loop
from atpt.toolbox import Toolbox

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

    def test_session_captures_flag(self):
        import modules.agent_offensive.loop as L
        scripted = iter([
            '{"listen": {"port": 4444}}',
            '{"session": "cat /home/web/user.txt"}',
            '{"done": true}',
        ])

        class FakeSess:
            def start_listener(self, port, scope=None):
                return {"ok": True, "listen": "192.168.141.21:4444"}

            def is_active(self):
                return True

            def wait_caught(self, t):
                return True

            def session_exec(self, cmd, timeout=45):
                return "flag{user_flag_captured}"

        orig = L.sess
        L.sess = FakeSess()
        try:
            assets, findings, summary = run_loop(
                goal="x", guard=guard(), scope=SCOPE, reason_fn=lambda p: next(scripted),
                max_steps=6, emit=lambda *a, **k: None,
                execute_fn=lambda argv: {"rc": 0, "out": "", "err": ""},
                harvest_fn=lambda a, r: ([], []))
        finally:
            L.sess = orig
        self.assertTrue(any(f["evidence"]["flag"] == "flag{user_flag_captured}" for f in findings))
        self.assertIn("done", summary.lower())

    def test_session_pivot_blocked_nonfatal(self):
        import modules.agent_offensive.loop as L
        scripted = iter(['{"session": "ssh 10.9.9.9"}', '{"done": true}'])
        events = []

        class FakeSess:
            def is_active(self):
                return True

            def wait_caught(self, t):
                return True

            def session_exec(self, cmd, timeout=45):
                return "SHOULD NOT RUN"

        orig = L.sess
        L.sess = FakeSess()
        try:
            _, _, summary = run_loop(
                goal="x", guard=guard(), scope=SCOPE, reason_fn=lambda p: next(scripted),
                max_steps=4, emit=lambda *a, **k: events.append(a),
                execute_fn=lambda argv: {}, harvest_fn=lambda a, r: ([], []))
        finally:
            L.sess = orig
        self.assertTrue(any("blocked" in str(e).lower() for e in events))
        self.assertIn("done", summary.lower())

    def test_no_reasoner_ends(self):
        assets, findings, summary = run_loop(
            goal="x", guard=guard(), reason_fn=lambda _: None, max_steps=5,
            emit=lambda *a, **k: None, execute_fn=lambda *a, **k: {}, harvest_fn=lambda a, r: ([], []))
        self.assertIn("no_reasoner", summary)


class LoopToolboxInjectTest(unittest.TestCase):
    def test_playbook_hint_injected_after_service_discovered(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tb = Toolbox(Path(tmp.name) / "toolbox")
        tb.save({"name": "ssh-cred-reuse", "applies_to": {"service_tags": ["ssh"]},
                 "steps": [{"command": ["hydra", "-l", "root", "{TARGET}"]}],
                 "success_note": "reused creds over ssh"})
        prompts = []
        # step 1 runs a real command (so an ssh asset is harvested); step 2's
        # prompt should then carry the ssh skill. A 'done' first action would end
        # the loop before any harvest, so the hint must be checked on prompt[1].
        scripted = iter(['{"command":["nmap","-Pn","10.1.1.5"]}', '{"done": true}'])

        def rf(p):
            prompts.append(p)
            return next(scripted)

        run_loop(goal="get a shell", guard=guard(), scope=SCOPE, reason_fn=rf,
                 max_steps=2, emit=lambda *a, **k: None,
                 execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=lambda a, r: ([{"asset_type": "service", "service": "ssh",
                                            "value": "10.1.1.5:22/ssh"}], []),
                 toolbox=tb)
        self.assertNotIn("LEARNED PLAYBOOK", prompts[0])   # no services discovered yet
        self.assertIn("LEARNED PLAYBOOK", prompts[1])
        self.assertIn("ssh-cred-reuse", prompts[1])

    def test_toolbox_none_leaves_prompt_clean(self):
        prompts = []

        def rf(p):
            prompts.append(p)
            return '{"done": true}'

        run_loop(goal="x", guard=guard(), reason_fn=rf, max_steps=1,
                 emit=lambda *a, **k: None,
                 execute_fn=lambda argv, timeout=300: {"rc": 0, "out": "", "err": ""},
                 harvest_fn=lambda a, r: ([], []))
        self.assertFalse(any("LEARNED PLAYBOOK" in p for p in prompts))


if __name__ == "__main__":
    unittest.main()
