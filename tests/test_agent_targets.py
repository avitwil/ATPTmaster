import unittest

from modules.agent_offensive.targets import extract_targets


class TargetsTest(unittest.TestCase):
    def test_nmap_ip(self):
        self.assertEqual(extract_targets(["nmap", "-sV", "-Pn", "10.1.1.5"]), ["10.1.1.5"])

    def test_curl_url_host(self):
        self.assertEqual(extract_targets(["curl", "-s", "http://10.1.1.5:80/x"]), ["10.1.1.5"])

    def test_flags_and_values_ignored(self):
        # -p 80 is a flag+value, not a target; only the host remains
        self.assertEqual(extract_targets(["nmap", "-p", "80", "host.example"]), ["host.example"])

    def test_multiple_deduped(self):
        self.assertEqual(extract_targets(["ffuf", "-u", "http://a.test/FUZZ", "-w", "a.test"]), ["a.test"])

    def test_empty(self):
        self.assertEqual(extract_targets(["id"]), [])

    def test_post_payload_is_not_a_target(self):
        # command-injection payload in --data must NOT be read as a connect target
        # (the real target is the in-scope URL). Regression from the live run.
        argv = ["curl", "-s", "-X", "POST", "http://10.114.164.13/internal/netcheck",
                "--data-urlencode", "host=$(cat /home/web/user.txt)"]
        self.assertEqual(extract_targets(argv), ["10.114.164.13"])

    def test_semicolon_injection_payload_ignored(self):
        argv = ["curl", "-X", "POST", "http://10.114.164.13/internal/netcheck",
                "-d", "host=127.0.0.1;id"]
        self.assertEqual(extract_targets(argv), ["10.114.164.13"])

    def test_header_and_cookie_values_ignored(self):
        argv = ["curl", "-H", "Host: evil.com", "-b", "sess=abc", "http://10.1.1.5/"]
        self.assertEqual(extract_targets(argv), ["10.1.1.5"])

    def test_curl_basic_auth_value_ignored(self):
        argv = ["curl", "-u", "admin:pass", "http://10.1.1.5/"]
        self.assertEqual(extract_targets(argv), ["10.1.1.5"])

    def test_ffuf_u_value_is_target(self):
        # -u is the URL for ffuf/gobuster (not curl creds)
        self.assertEqual(extract_targets(["ffuf", "-u", "http://a.test/FUZZ", "-w", "list.txt"]), ["a.test"])

    def test_out_of_scope_url_still_extracted(self):
        # security: a genuinely out-of-scope connect target must still be seen
        self.assertEqual(extract_targets(["curl", "http://evil.com/"]), ["evil.com"])


if __name__ == "__main__":
    unittest.main()
