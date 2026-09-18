import unittest

from modules.agent_offensive.executor import execute, harvest


class ExecTest(unittest.TestCase):
    def test_execute_uses_injected_runner(self):
        calls = {}

        def fake(argv, timeout=300):
            calls["argv"] = argv
            return (0, "OK", "")

        r = execute(["nmap", "10.1.1.5"], runner=fake)
        self.assertEqual(r["rc"], 0)
        self.assertEqual(r["out"], "OK")
        self.assertEqual(calls["argv"], ["nmap", "10.1.1.5"])

    def test_harvest_nmap_ports(self):
        out = "Nmap scan report for 10.1.1.5\n22/tcp open ssh\n80/tcp open http\n"
        assets, findings = harvest(["nmap", "-Pn", "10.1.1.5"], {"rc": 0, "out": out, "err": ""})
        vals = sorted(a["value"] for a in assets)
        self.assertEqual(vals, ["10.1.1.5:22/ssh", "10.1.1.5:80/http"])
        self.assertEqual(findings, [])

    def test_harvest_nothing(self):
        self.assertEqual(harvest(["id"], {"rc": 0, "out": "uid=0", "err": ""}), ([], []))

    def test_harvest_curl_web_endpoint(self):
        out = "HTTP/1.1 200 OK\r\nServer: Gunicorn\r\n\r\n<html>"
        assets, _ = harvest(["curl", "-s", "-i", "http://10.1.1.5/"], {"rc": 0, "out": out, "err": ""})
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["asset_type"], "web_endpoint")
        self.assertEqual(assets[0]["value"], "http://10.1.1.5/")
        self.assertEqual(assets[0]["http_status"], 200)

    def test_harvest_whatweb_endpoint(self):
        assets, _ = harvest(["whatweb", "-a", "3", "http://10.1.1.5/"], {"rc": 0, "out": "nginx", "err": ""})
        self.assertEqual(assets[0]["asset_type"], "web_endpoint")

    def test_harvest_gobuster_paths(self):
        out = "http://10.1.1.5/admin (Status: 200)\nhttp://10.1.1.5/login (Status: 302)\n"
        assets, _ = harvest(["gobuster", "dir", "-u", "http://10.1.1.5/"], {"rc": 0, "out": out, "err": ""})
        paths = [a["value"] for a in assets if a["asset_type"] == "web_path"]
        self.assertIn("http://10.1.1.5/admin", paths)


if __name__ == "__main__":
    unittest.main()
