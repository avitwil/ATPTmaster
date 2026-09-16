"""Shared CLI-wrapper helper: binary presence + never-raising scoped subprocess."""
import unittest

from atpt import toolwrap


class ToolwrapTest(unittest.TestCase):
    def test_have_false_for_missing(self):
        self.assertFalse(toolwrap.have("definitely_not_a_binary_xyz_123"))

    def test_have_true_for_python(self):
        self.assertTrue(toolwrap.have("python3") or toolwrap.have("python"))

    def test_run_missing_binary_noops(self):
        rc, out, err = toolwrap.run(["definitely_not_a_binary_xyz_123", "--x"])
        self.assertEqual(rc, -1)
        self.assertEqual(out, "")
        self.assertIn("not installed", err)

    def test_run_empty_argv_noops(self):
        rc, out, err = toolwrap.run([])
        self.assertEqual(rc, -1)

    def test_run_real_command(self):
        rc, out, err = toolwrap.run(["python3", "-c", "print('hi')"])
        self.assertEqual(rc, 0)
        self.assertIn("hi", out)
