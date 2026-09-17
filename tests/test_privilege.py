"""Session-memory sudo state + toolwrap sudo invocation. Passwords stay in RAM."""
import unittest

from atpt import privilege, toolwrap


class PrivilegeTest(unittest.TestCase):
    def setUp(self):
        privilege.reset()

    def tearDown(self):
        privilege.reset()

    def test_default_not_allowed(self):
        self.assertFalse(privilege.is_allowed())
        prefix, stdin = privilege.sudo_invocation()
        self.assertIsNone(prefix)
        self.assertIsNone(stdin)

    def test_allowed_with_password(self):
        privilege.set_allowed(True)
        privilege.set_password("hunter2")
        prefix, stdin = privilege.sudo_invocation()
        self.assertEqual(prefix, ["sudo", "-S", "-p", ""])
        self.assertEqual(stdin, "hunter2\n")

    def test_allowed_without_password_uses_noninteractive(self):
        privilege.set_allowed(True)          # NOPASSWD path
        prefix, stdin = privilege.sudo_invocation()
        self.assertEqual(prefix, ["sudo", "-n"])
        self.assertIsNone(stdin)

    def test_clear_password_wipes_it(self):
        privilege.set_allowed(True)
        privilege.set_password("secret")
        privilege.clear_password()
        prefix, stdin = privilege.sudo_invocation()
        self.assertEqual(prefix, ["sudo", "-n"])   # allowed but no pw
        self.assertIsNone(stdin)

    def test_has_password_never_returns_value(self):
        privilege.set_password("s3cr3t")
        # the module exposes presence, never the value
        self.assertTrue(privilege.has_password())
        self.assertFalse(hasattr(privilege, "PASSWORD"))


class ToolwrapSudoTest(unittest.TestCase):
    def setUp(self):
        privilege.reset()

    def tearDown(self):
        privilege.reset()

    def test_sudo_not_enabled_returns_minus3(self):
        rc, out, err = toolwrap.run(["id"], sudo=True)
        self.assertEqual(rc, -3)
        self.assertIn("sudo not enabled", err)

    def test_non_sudo_path_unchanged(self):
        rc, out, err = toolwrap.run(["python3", "-c", "print('hi')"])
        self.assertEqual(rc, 0)
        self.assertIn("hi", out)

    def test_sudo_builds_argv_and_feeds_stdin(self):
        privilege.set_allowed(True)
        privilege.set_password("pw")
        seen = {}

        def fake_run(argv, capture_output, text, timeout, input=None):
            seen["argv"] = argv
            seen["input"] = input

            class R:
                returncode, stdout, stderr = 0, "", ""
            return R()

        import subprocess
        orig = subprocess.run
        subprocess.run = fake_run
        try:
            toolwrap.run(["nmap", "-sS", "10.0.0.1"], sudo=True)
        finally:
            subprocess.run = orig
        self.assertEqual(seen["argv"][:4], ["sudo", "-S", "-p", ""])
        self.assertIn("nmap", seen["argv"])
        self.assertEqual(seen["input"], "pw\n")
