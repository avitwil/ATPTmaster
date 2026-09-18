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


class _Completed:
    """Stand-in for subprocess.CompletedProcess (elevated-kill is never real)."""
    returncode = 0
    stdout = ""
    stderr = ""


class VpnTest(unittest.TestCase):
    def setUp(self):
        self._popen = vpn.subprocess.Popen
        self._which = vpn.shutil.which
        self._run = vpn.subprocess.run
        self._register = vpn.atexit.register
        self.run_calls = []          # (argv, kwargs) of every subprocess.run
        self.registered = []         # callables handed to atexit.register
        vpn.subprocess.run = lambda argv, **k: (
            self.run_calls.append((argv, k)) or _Completed())
        vpn.atexit.register = lambda fn, *a, **k: self.registered.append(fn)
        vpn.shutil.which = lambda b: "/usr/sbin/openvpn"          # openvpn present
        vpn._ATEXIT_REGISTERED = False
        vpn.disconnect()
        self.run_calls.clear()       # ignore any teardown fired during reset

    def tearDown(self):
        vpn.subprocess.Popen = self._popen
        vpn.shutil.which = self._which
        vpn.disconnect()
        vpn.subprocess.run = self._run
        vpn.atexit.register = self._register

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

    def _connect(self, sudo_password):
        d = tempfile.mkdtemp()
        cfg = Path(d) / "box.ovpn"
        cfg.write_text("client\n")
        vpn.subprocess.Popen = lambda *a, **k: _FakeProc(
            ["Initialization Sequence Completed\n"])
        vpn.connect(str(cfg), sudo_password)
        return str(cfg)

    def test_disconnect_elevated_kill_uses_sudo_password(self):
        cfg = self._connect("s3cret")
        self.run_calls.clear()
        vpn.disconnect()
        kills = [c for c in self.run_calls if "pkill" in c[0]]
        self.assertTrue(kills, "disconnect must issue an elevated pkill for a root openvpn")
        argv, kw = kills[-1]
        self.assertEqual(argv[:4], ["sudo", "-S", "-p", ""])          # password path
        self.assertIn(cfg, " ".join(argv))                            # only our tunnel
        self.assertEqual(kw.get("input"), "s3cret\n")                 # pw fed on stdin
        self.assertIsNone(vpn.status()["config"])                     # state cleared

    def test_disconnect_elevated_kill_nopasswd(self):
        cfg = self._connect(None)                                     # NOPASSWD sudoers
        self.run_calls.clear()
        vpn.disconnect()
        kills = [c for c in self.run_calls if "pkill" in c[0]]
        self.assertTrue(kills)
        argv, _ = kills[-1]
        self.assertEqual(argv[:2], ["sudo", "-n"])
        self.assertIn(cfg, " ".join(argv))

    def test_connect_registers_atexit_teardown(self):
        self._connect("pw")
        self.assertIn(vpn.disconnect, self.registered)                # dies with the app
