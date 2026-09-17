# bench/tests/test_cli.py
import io
import contextlib
import unittest
from bench import cli


class CLI(unittest.TestCase):
    def test_parser_defaults(self):
        args = cli.build_parser().parse_args(["run", "--suite", "xbow", "--smoke", "3"])
        self.assertEqual(args.suite, "xbow")
        self.assertEqual(args.smoke, 3)
        self.assertEqual(args.primary, "opus")
        self.assertEqual(args.fallback, "deephat")

    def test_dry_run_prints_ladder_and_exits_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["run", "--suite", "xbow", "--smoke", "2", "--dry-run"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("opus", out)
        self.assertIn("deephat", out)
        self.assertIn("dry-run", out.lower())


if __name__ == "__main__":
    unittest.main()
