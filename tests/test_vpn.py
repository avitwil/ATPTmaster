"""Background VPN manager (openvpn mocked — no real tunnel)."""
import io
import tempfile
import threading
import time
import unittest
from pathlib import Path

from atpt import vpn


class _FakeProc:
    def __init__(self, lines):
        self.stdin = io.StringIO()
        self._it = iter(lines)
        self.returncode = None
        self._alive = True
        self._done = threading.Event()

    @property
    def stdout(self):
        return self

    def readline(self):
        try:
            return next(self._it)
        except StopIteration:
            self._done.wait(2)          # live process: block until terminated
            return ""

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self._alive = False
        self.returncode = 0
        self._done.set()

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self._alive = False
        self._done.set()


class VpnTest(unittest.TestCase):
    def setUp(self):
        vpn.disconnect()
        self._popen = vpn.subprocess.Popen
        self._which = vpn.shutil.which
        vpn.shutil.which = lambda b: "/usr/sbin/openvpn"          # openvpn present

    def tearDown(self):
        vpn.subprocess.Popen = self._popen
        vpn.shutil.which = self._which
        vpn.disconnect()

    def test_missing_config_errors(self):
        r = vpn.connect("/nope/does-not-exist.ovpn", "pw")
        self.assertFalse(r["ok"])
        self.assertIn("not found", r["error"])

    def test_connect_marks_connected_then_disconnect(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "box.ovpn"
            cfg.write_text("client\n")
            fp = _FakeProc(["OpenVPN 2.6 starting\n", "Initialization Sequence Completed\n"])
            vpn.subprocess.Popen = lambda *a, **k: fp
            r = vpn.connect(str(cfg), "pw")
            self.assertTrue(r["ok"])
            self.assertEqual(fp.stdin.getvalue(), "pw\n")          # sudo password fed on stdin
            for _ in range(50):
                if vpn.status()["status"] == "connected":
                    break
                time.sleep(0.02)
            self.assertEqual(vpn.status()["status"], "connected")
            self.assertTrue(vpn.is_up())
            self.assertTrue(vpn.disconnect()["ok"])
            self.assertEqual(vpn.status()["status"], "down")
