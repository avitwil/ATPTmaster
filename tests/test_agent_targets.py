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


if __name__ == "__main__":
    unittest.main()
