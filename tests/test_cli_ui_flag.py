"""`atpt --u` (and --ui / -u) launches the web console; bare `atpt` shows help."""
import unittest

from atpt import cli


class CliUiFlagTest(unittest.TestCase):
    def setUp(self):
        self._serve = cli.cmd_serve
        self.calls = []
        cli.cmd_serve = lambda args: self.calls.append((args.port, args.host)) or 0

    def tearDown(self):
        cli.cmd_serve = self._serve

    def test_u_flag_launches_serve_defaults(self):
        cli.main(["--u"])
        self.assertEqual(self.calls, [(8787, "127.0.0.1")])

    def test_ui_aliases_and_port(self):
        for flag in ("--ui", "-u"):
            self.calls.clear()
            cli.main([flag, "--port", "9001"])
            self.assertEqual(self.calls, [(9001, "127.0.0.1")])

    def test_bare_atpt_shows_help_no_error(self):
        # no subcommand -> prints help and returns 0 (does not raise SystemExit)
        self.assertEqual(cli.main([]), 0)
        self.assertEqual(self.calls, [])
