import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory, mkdtemp

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
    # project_dir is a fresh temp dir, not ".": once enabled, run() now
    # constructs a Toolbox(project_dir / "toolbox") and reindexes it, so "."
    # would litter the repo root with a real toolbox/index.db on every run.
    return RunContext(engagement=eng, scope={"in_scope_cidrs": ["10.1.1.0/24"]},
                      store=_Store(), project_dir=Path(mkdtemp(prefix="atpt-agent-module-")),
                      reasoner=reasoner)


class ModuleTest(unittest.TestCase):
    def test_disabled_is_noop(self):
        res = _mod().run(_ctx({}))
        self.assertTrue(res.ok)
        self.assertEqual(res.assets, [])
        self.assertIn("disabled", res.summary)

    def test_manifest_recon_and_not_engine_intrusive(self):
        # Non-intrusive at the manifest level so a DISABLED agent never gates a
        # normal run; its real gate is the startup scope-confirmation + the
        # per-command ScopeGuard, not the engine's per-module pause.
        m = Manifest.from_file(Path("modules/agent_offensive/module.json"))
        self.assertEqual(m.phase, "recon")
        self.assertFalse(m.intrusive)

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


def _manifest():
    return Manifest(id="agent_offensive", name="Agent", phase="recon",
                    entrypoint="module:AgentOffensive", intrusive=True)


class _Reasoner:
    """Scripted: first the loop step, then the distillation skill JSON."""
    def __init__(self, steps):
        self._it = iter(steps)

    def reason(self, prompt, phase):
        class R:
            text = next(self._it)
        return R()


class ModuleToolboxTest(unittest.TestCase):
    def test_successful_run_persists_a_skill_file(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pd = Path(tmp.name)

        # A fake store: only the pieces the module/ctx touch.
        class Store:
            def add_event(self, *a, **k): pass

        eng = {"id": "e1", "config": json.dumps({"offensive_agent": {"enabled": True,
                "max_steps": 3, "allow_bins": []}})}
        scope = {"in_scope_cidrs": ["10.1.1.5/32"]}
        # Keep it to command-then-done (no session step — that would touch the real
        # session module). The nmap output carries a flag the loop's flag-scanner
        # turns into a finding, so the run "succeeds" and distillation fires.
        steps = [
            '{"command":["nmap","-Pn","10.1.1.5"]}',   # step 1: output carries flag{seed}
            '{"done": true}',                           # step 2: end
            # distillation reply (loop ended with a finding):
            '{"name":"nmap-open","applies_to":{"service_tags":["http"]},'
            '"steps":[{"command":["nmap","-Pn","10.1.1.5"]}],"success_note":"scan"}',
        ]
        ctx = RunContext(engagement=eng, scope=scope, store=Store(), project_dir=pd,
                         reasoner=_Reasoner(steps), goals="capture the flag flag{seed}")
        mod = AgentOffensive(_manifest(), pd)
        # monkeypatch execute to emit a flag in output
        import modules.agent_offensive.module as M
        orig = M.execute
        M.execute = lambda argv, timeout=300: {"rc": 0, "out": "flag{seed}", "err": ""}
        try:
            res = mod.run(ctx)
        finally:
            M.execute = orig
        self.assertTrue(res.ok)
        files = list((pd / "toolbox").glob("*.json"))
        self.assertTrue(files, "a skill file should have been written")
        self.assertEqual(json.loads(files[0].read_text())["name"], "nmap-open")


if __name__ == "__main__":
    unittest.main()
