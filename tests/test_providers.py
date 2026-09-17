"""Curated subscription-CLI registry: detection + install/login command lookup."""
import unittest

from atpt import providers


class ProvidersTest(unittest.TestCase):
    def test_registry_has_curated_clis(self):
        for name in ("claude", "gemini", "codex"):
            self.assertIn(name, providers.REGISTRY)
            entry = providers.REGISTRY[name]
            self.assertTrue(entry["binary"])
            self.assertIsInstance(entry["install"], list)
            self.assertIsInstance(entry["login"], list)

    def test_status_known_installed_binary(self):
        # 'python3' is guaranteed present in the test env; use it as a stand-in binary.
        st = providers.status("python3")
        self.assertTrue(st["installed"])
        self.assertTrue(st["path"])

    def test_status_missing_binary(self):
        st = providers.status("definitely_absent_bin_xyz")
        self.assertFalse(st["installed"])
        self.assertIsNone(st["path"])

    def test_status_by_provider_name(self):
        st = providers.status("claude")
        self.assertEqual(st["binary"], "claude")
        self.assertTrue(st["known"])

    def test_unknown_provider_name_not_known(self):
        st = providers.status("my-custom-cmd")
        self.assertFalse(st["known"])
        self.assertEqual(st["binary"], "my-custom-cmd")

    def test_login_argv_lookup(self):
        self.assertIsInstance(providers.login_argv("codex"), list)
        self.assertIsNone(providers.login_argv("unknown-xyz"))

    def test_install_refuses_unknown(self):
        rc, out, err = providers.install("unknown-xyz")
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown", err.lower())

    def test_install_runs_registered_command(self):
        seen = {}

        def fake_run(argv, capture_output, text, timeout):
            seen["argv"] = argv

            class R:
                returncode, stdout, stderr = 0, "installed", ""
            return R()

        import subprocess
        orig = subprocess.run
        subprocess.run = fake_run
        try:
            rc, out, err = providers.install("claude")
        finally:
            subprocess.run = orig
        self.assertEqual(rc, 0)
        self.assertEqual(seen["argv"], providers.REGISTRY["claude"]["install"])
