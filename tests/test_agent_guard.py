import unittest

from modules.agent_offensive.guard import ScopeGuard, DEFAULT_ALLOW

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
