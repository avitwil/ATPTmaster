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


if __name__ == "__main__":
    unittest.main()
