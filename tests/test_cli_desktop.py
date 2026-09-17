"""`atpt desktop` (and --app / --desktop / -d) launches the desktop app."""
import unittest

from atpt import cli


class CliDesktopTest(unittest.TestCase):
    def setUp(self):
        self._launch = cli.cmd_desktop
        self.calls = []
        cli.cmd_desktop = lambda args: self.calls.append(args.host) or 0

    def tearDown(self):
        cli.cmd_desktop = self._launch

    def test_desktop_subcommand(self):
        cli.main(["desktop"])
        self.assertEqual(self.calls, ["127.0.0.1"])

    def test_app_aliases(self):
        for flag in ("--app", "--desktop", "-d"):
            self.calls.clear()
            cli.main([flag])
            self.assertEqual(self.calls, ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
