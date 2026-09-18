# bench/tests/test_xbow_runner.py
import os
import tempfile
import textwrap
import unittest
from bench.actions import Action
from bench import xbow_runner as X


def make_bench(root, cid, level="2", name="Demo"):
    d = os.path.join(root, cid)
    os.makedirs(d)
    with open(os.path.join(d, "benchmark.json"), "w") as f:
        f.write(textwrap.dedent(f'''
        {{"name":"{name}","level":"{level}","win_condition":"flag","tags":["idor"]}}'''))
    open(os.path.join(d, "docker-compose.yml"), "w").close()
    return d


class Discover(unittest.TestCase):
    def test_discovers_and_sorts_by_level(self):
        with tempfile.TemporaryDirectory() as root:
            make_bench(root, "XBEN-002-24", level="3")
            make_bench(root, "XBEN-001-24", level="1")
            got = X.discover_challenges(root, limit=2)
            self.assertEqual([c["id"] for c in got], ["XBEN-001-24", "XBEN-002-24"])
            self.assertEqual(got[0]["level"], "1")

    def test_limit(self):
        with tempfile.TemporaryDirectory() as root:
            for i in range(5):
                make_bench(root, f"XBEN-00{i}-24", level=str(i))
            self.assertEqual(len(X.discover_challenges(root, limit=3)), 3)


class Executor(unittest.TestCase):
    def test_submit_correct_flag_solves(self):
        ex = X.XbowExecutor("http://t", "flag{abc}", runner=lambda k, p: "ok")
        obs = ex.run(Action("", "submit_flag", {"flag": "flag{abc}"}))
        self.assertTrue(obs.done and obs.success)

    def test_submit_wrong_flag_not_success(self):
        ex = X.XbowExecutor("http://t", "flag{abc}", runner=lambda k, p: "ok")
        obs = ex.run(Action("", "submit_flag", {"flag": "nope"}))
        self.assertTrue(obs.done)
        self.assertFalse(obs.success)

    def test_http_request_delegates_to_runner(self):
        seen = {}
        def runner(kind, payload):
            seen["kind"], seen["payload"] = kind, payload
            return "HTTP/1.1 200"
        ex = X.XbowExecutor("http://t", "f", runner=runner)
        obs = ex.run(Action("", "http_request", {"path": "/orders/2"}))
        self.assertEqual(seen["kind"], "http")
        self.assertIn("200", obs.text)


class CurlArgs(unittest.TestCase):
    def test_dict_data_is_json_encoded_and_all_str(self):
        args = X._curl_args("http://t", {"path": "/p", "method": "post", "data": {"id": 2}})
        self.assertTrue(all(isinstance(a, str) for a in args))
        self.assertIn("http://t/p", args)
        self.assertIn("POST", args)                 # method upper-cased
        i = args.index("-d")
        self.assertEqual(args[i + 1], '{"id": 2}')  # dict serialized to JSON

    def test_str_data_passthrough(self):
        args = X._curl_args("http://t", {"path": "/", "data": "id=2"})
        i = args.index("-d")
        self.assertEqual(args[i + 1], "id=2")

    def test_no_data_no_dflag(self):
        args = X._curl_args("http://t", {"path": "/"})
        self.assertNotIn("-d", args)


class Suite(unittest.TestCase):
    def test_teardown_always_runs(self):
        events = []

        class FakeCompose:
            def up(self, d, flag): events.append(("up", d)); return "http://127.0.0.1:8080"
            def down(self, d): events.append(("down", d))

        class BrainSolves:
            def think(self, t):
                return ('```json\n{"tool":"submit_flag","args":{"flag":"flag{dummy}"}}\n```',
                        "opus")

        with tempfile.TemporaryDirectory() as root:
            make_bench(root, "XBEN-001-24", level="1")
            chals = X.discover_challenges(root)
            eps = X.run_suite(chals, BrainSolves(), compose=FakeCompose(), max_steps=3)
        self.assertEqual(events[0][0], "up")
        self.assertEqual(events[-1][0], "down")           # teardown ran
        self.assertEqual(len(eps), 1)


if __name__ == "__main__":
    unittest.main()
