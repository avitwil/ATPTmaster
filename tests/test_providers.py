"""Curated subscription-CLI registry: detection, autonomous install planning,
and sudo-driven execution (deps + global install)."""
import subprocess
import unittest

from atpt import privilege, providers


class ProvidersRegistryTest(unittest.TestCase):
    def test_registry_has_curated_clis(self):
        for name in ("claude", "gemini", "codex"):
            self.assertIn(name, providers.REGISTRY)
            e = providers.REGISTRY[name]
            self.assertTrue(e["binary"] and e["pkg"])
            self.assertIsInstance(e["args"], list)
            self.assertIsInstance(e["login"], list)

    def test_resolved_cmd_uses_bin_path_and_args(self):
        # not installed in the test env -> falls back to the bare binary + args
        self.assertEqual(providers.resolved_cmd("claude"), "claude -p")
        # once resolvable, uses the full path
        orig = providers.shutil.which
        providers.shutil.which = lambda b: "/usr/local/bin/claude" if b == "claude" else None
        try:
            self.assertEqual(providers.resolved_cmd("claude"), "/usr/local/bin/claude -p")
        finally:
            providers.shutil.which = orig

    def test_status_reports_resolved_cmd(self):
        st = providers.status("claude")
        self.assertEqual(st["binary"], "claude")
        self.assertTrue(st["known"])
        self.assertEqual(st["cmd"], providers.resolved_cmd("claude"))

    def test_login_argv_lookup(self):
        self.assertIsInstance(providers.login_argv("codex"), list)
        self.assertIsNone(providers.login_argv("unknown-xyz"))


class InstallPlanTest(unittest.TestCase):
    def setUp(self):
        self._which = providers.shutil.which

    def tearDown(self):
        providers.shutil.which = self._which

    def _fake_which(self, present):
        providers.shutil.which = lambda b: ("/usr/bin/" + b) if b in present else None

    def test_already_installed_no_steps(self):
        self._fake_which({"claude"})
        self.assertEqual(providers.install_steps("claude"), [])

    def test_missing_npm_adds_node_dependency_first(self):
        self._fake_which(set())                       # nothing present
        steps = providers.install_steps("claude")
        self.assertEqual(len(steps), 2)
        self.assertIn("nodejs", steps[0]["argv"])     # deps first
        self.assertTrue(steps[0]["sudo"])
        self.assertIn("@anthropic-ai/claude-code", steps[1]["argv"])
        self.assertTrue(steps[1]["sudo"])

    def test_npm_present_only_installs_cli(self):
        self._fake_which({"npm"})
        steps = providers.install_steps("codex")
        self.assertEqual(len(steps), 1)
        self.assertIn("@openai/codex", steps[0]["argv"])

    def test_unknown_provider_none(self):
        self.assertIsNone(providers.install_steps("nope"))

    def test_needs_sudo(self):
        self._fake_which(set())
        self.assertTrue(providers.needs_sudo("claude"))
        self._fake_which({"claude"})
        self.assertFalse(providers.needs_sudo("claude"))   # nothing to do


class RunInstallTest(unittest.TestCase):
    def setUp(self):
        privilege.reset()
        self._which = providers.shutil.which
        self._run = subprocess.run
        providers.shutil.which = lambda b: None          # nothing installed

    def tearDown(self):
        privilege.reset()
        providers.shutil.which = self._which
        subprocess.run = self._run

    def test_requests_sudo_when_no_password(self):
        res = providers.run_install("claude", sudo_password=None)
        self.assertTrue(res.get("needs_sudo"))

    def test_runs_steps_under_sudo_with_password(self):
        calls = []

        def fake_run(argv, capture_output=True, text=True, timeout=None, input=None):
            calls.append((argv, input))
            class R: returncode, stdout, stderr = 0, "ok", ""
            return R()
        subprocess.run = fake_run
        res = providers.run_install("claude", sudo_password="pw123")
        # every privileged step is prefixed with sudo -S and fed the password on stdin
        sudo_calls = [c for c in calls if c[0][:2] == ["sudo", "-S"]]
        self.assertTrue(sudo_calls)
        for argv, inp in sudo_calls:
            self.assertEqual(inp, "pw123\n")
        # the actual CLI package install happened
        joined = [" ".join(a) for a, _ in calls]
        self.assertTrue(any("@anthropic-ai/claude-code" in j for j in joined))

    def test_password_never_in_argv(self):
        captured = []

        def fake_run(argv, capture_output=True, text=True, timeout=None, input=None):
            captured.append(argv)
            class R: returncode, stdout, stderr = 0, "", ""
            return R()
        subprocess.run = fake_run
        providers.run_install("gemini", sudo_password="topsecret")
        for argv in captured:
            self.assertNotIn("topsecret", argv)
