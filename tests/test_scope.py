"""Scope oracle — the Python-side gate intrusive modules use before touching a host."""
import unittest

from atpt.scope import in_scope

SCOPE = {
    "in_scope_domains": ["acme.com"],
    "in_scope_cidrs": ["10.0.0.0/24"],
    "out_of_scope": ["secure.acme.com"],
}


class ScopeTest(unittest.TestCase):
    def test_in_scope_domain_and_subdomain(self):
        self.assertTrue(in_scope(SCOPE, "acme.com"))
        self.assertTrue(in_scope(SCOPE, "api.acme.com"))
        self.assertTrue(in_scope(SCOPE, "https://api.acme.com/login"))

    def test_in_scope_cidr(self):
        self.assertTrue(in_scope(SCOPE, "10.0.0.5"))
        self.assertTrue(in_scope(SCOPE, "http://10.0.0.5:8080/x"))

    def test_out_of_scope_deny_wins(self):
        self.assertFalse(in_scope(SCOPE, "secure.acme.com"))
        self.assertFalse(in_scope(SCOPE, "https://secure.acme.com/"))

    def test_unlisted_is_out(self):
        self.assertFalse(in_scope(SCOPE, "evil.com"))
        self.assertFalse(in_scope(SCOPE, "10.9.9.9"))

    def test_empty_scope_denies(self):
        self.assertFalse(in_scope({}, "acme.com"))

    def test_out_of_scope_cidr_deny_wins(self):
        s = {"in_scope_cidrs": ["10.0.0.0/24"], "out_of_scope_cidrs": ["10.0.0.5/32", "10.0.0.64/26"]}
        self.assertTrue(in_scope(s, "10.0.0.9"))        # in the /24, not denied
        self.assertFalse(in_scope(s, "10.0.0.5"))       # single-IP deny
        self.assertFalse(in_scope(s, "10.0.0.70"))      # inside denied /26
        self.assertFalse(in_scope(s, "http://10.0.0.5:8080/"))

    def test_userinfo_stripped(self):
        self.assertTrue(in_scope(SCOPE, "http://user:pass@acme.com/"))
        # a credential-embedded URL pointing at an out-of-scope host is still out
        self.assertFalse(in_scope(SCOPE, "http://acme.com@evil.com/"))

    def test_wildcard_domain(self):
        s = {"in_scope_domains": ["*.acme.com"]}
        self.assertTrue(in_scope(s, "api.acme.com"))
        self.assertTrue(in_scope(s, "acme.com"))
        self.assertFalse(in_scope(s, "evil.com"))

    def test_ipv6(self):
        s = {"in_scope_cidrs": ["2001:db8::/32"]}
        self.assertTrue(in_scope(s, "2001:db8::1"))
        self.assertTrue(in_scope(s, "http://[2001:db8::1]:8080/x"))
        self.assertFalse(in_scope(s, "2001:dead::1"))
