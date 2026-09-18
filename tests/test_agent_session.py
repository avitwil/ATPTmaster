"""Reverse-shell session over a real loopback socket (no external network).
A fake 'shell' thread connects back to the listener and echoes marker-framed
output, exercising the actual start_listener/wait_caught/session_exec/close path."""
import re
import socket
import threading
import time
import unittest

from modules.agent_offensive import session


def _fake_shell(port, host="127.0.0.1", canned=b"uid=0(root) gid=0(root)\n"):
    """Connect back like a caught reverse shell: for each `cmd; echo MARKER`,
    reply with canned output then the marker line."""
    c = socket.create_connection((host, port), timeout=5)
    c.sendall(b"sh: no job control\n")            # banner
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
            line = data.decode(errors="replace")
            c.sendall(canned)
            m = re.search(r"echo (__ATPT_\w+__)", line)
            if m:
                c.sendall((m.group(1) + "\n").encode())
    except OSError:
        pass


class SessionTest(unittest.TestCase):
    def tearDown(self):
        session.close()

    def test_reverse_shell_roundtrip(self):
        r = session.start_listener(0, bind_ip="127.0.0.1")
        self.assertTrue(r["ok"], r)
        threading.Thread(target=_fake_shell, args=(r["port"],), daemon=True).start()
        self.assertTrue(session.wait_caught(5))
        self.assertTrue(session.is_active())
        out = session.session_exec("id", timeout=5)
        self.assertIn("uid=0", out)
        self.assertNotIn("__ATPT_", out)           # marker stripped
        session.close()
        self.assertFalse(session.is_active())

    def test_out_of_scope_caller_rejected(self):
        # a caller not in scope must be dropped
        r = session.start_listener(0, scope={"in_scope_cidrs": ["10.1.1.0/24"]},
                                   bind_ip="127.0.0.1")
        self.assertTrue(r["ok"])
        threading.Thread(target=_fake_shell, args=(r["port"],), daemon=True).start()
        self.assertFalse(session.wait_caught(3))    # 127.0.0.1 not in 10.1.1.0/24
        self.assertEqual(session.status()["status"], "rejected")

    def test_in_scope_caller_accepted(self):
        r = session.start_listener(0, scope={"in_scope_cidrs": ["127.0.0.0/8"]},
                                   bind_ip="127.0.0.1")
        threading.Thread(target=_fake_shell, args=(r["port"],), daemon=True).start()
        self.assertTrue(session.wait_caught(5))
        self.assertEqual(session.status()["peer"], "127.0.0.1")

    def test_exec_without_session(self):
        session.close()
        self.assertIn("no active session", session.session_exec("id"))


if __name__ == "__main__":
    unittest.main()
