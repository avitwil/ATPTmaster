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

    def test_cookie_jar_saves_and_sends(self):
        args = X._curl_args("http://t", {"path": "/"}, cookie_jar="/tmp/jar")
        self.assertIn("-c", args)
        self.assertIn("-b", args)
        # both -c and -b point at the jar
        self.assertEqual(args[args.index("-c") + 1], "/tmp/jar")
        self.assertEqual(args[args.index("-b") + 1], "/tmp/jar")

    def test_headers_added(self):
        args = X._curl_args("http://t", {"path": "/",
                                         "headers": {"Authorization": "Bearer x"}})
        self.assertIn("-H", args)
        self.assertIn("Authorization: Bearer x", args)


class PortCandidates(unittest.TestCase):
    def test_reads_container_port_from_config(self):
        cfg = {"services": {
            "web": {"ports": [{"mode": "ingress", "target": 8000, "protocol": "tcp"}]},
            "db": {}}}
        cands = X._port_candidates(cfg, ["web", "db"])
        self.assertIn(("web", "8000"), cands)              # real port, not 80
        self.assertFalse(any(svc == "db" for svc, _ in cands))

    def test_port_80_service_still_found(self):
        cfg = {"services": {"app": {"ports": [{"target": 80}]}}}
        self.assertEqual(X._port_candidates(cfg, ["app"]), [("app", "80")])

    def test_fallback_common_ports_when_config_has_none(self):
        cands = X._port_candidates({"services": {"web": {}}}, ["web"])
        ports = [p for svc, p in cands if svc == "web"]
        self.assertIn("80", ports)
        self.assertIn("8000", ports)


class PickBaseUrl(unittest.TestCase):
    _DJANGO_400 = ("<h1>DisallowedHost at /</h1><pre>Invalid HTTP_HOST header: "
                   "'127.0.0.1:32770'. You may need to add '127.0.0.1' to ALLOWED_HOSTS.</pre>")

    def test_switches_to_localhost_when_127_rejected(self):
        def probe(url):
            return self._DJANGO_400 if "127.0.0.1" in url else "<h1>Welcome</h1>"
        self.assertEqual(X._pick_base_url("32770", probe=probe),
                         "http://localhost:32770")

    def test_keeps_127_when_accepted(self):
        got = X._pick_base_url("8080", probe=lambda url: "<html>ok</html>")
        self.assertEqual(got, "http://127.0.0.1:8080")   # first candidate, no probe switch

    def test_all_rejected_falls_back_to_default(self):
        got = X._pick_base_url("9000", probe=lambda url: self._DJANGO_400)
        self.assertEqual(got, "http://127.0.0.1:9000")

    def test_host_rejected_detects_django_page(self):
        self.assertTrue(X._host_rejected(self._DJANGO_400))
        self.assertFalse(X._host_rejected("<h1>Login</h1>"))
        self.assertFalse(X._host_rejected(""))


class HttpResultFormat(unittest.TestCase):
    def test_nonempty_passthrough(self):
        out = X._format_http_result("HTTP/1.1 200 OK\n\nbody", 0, "", "http://t")
        self.assertIn("200 OK", out)

    def test_empty_becomes_diagnostic(self):
        out = X._format_http_result("", 7, "Connection refused", "http://127.0.0.1:80")
        self.assertIn("no HTTP response", out)
        self.assertIn("http://127.0.0.1:80", out)          # names the dead target
        self.assertIn("exit 7", out)
        self.assertIn("Connection refused", out)

    def test_strips_style_script_and_caps(self):
        body = ("HTTP/1.1 200 OK\n\n<html><h1>Hello, {{7*7}}=49</h1>"
                "<style>" + "x{color:red}" * 5000 + "</style>"
                "<script>" + "var a=1;" * 5000 + "</script></html>")
        out = X._trim_http(body)
        self.assertIn("49", out)                            # the useful reflection survives
        self.assertNotIn("color:red", out)                  # CSS boilerplate stripped
        self.assertNotIn("var a=1", out)                    # JS boilerplate stripped
        self.assertLessEqual(len(out), 2600)                # capped (~2500 + marker)


class ComposeBuildArgs(unittest.TestCase):
    def test_up_injects_flag_as_build_arg(self):
        # ~13 challenges declare `ARG FLAG` but omit it from compose build.args,
        # so the env-var route baked an empty flag. Compose.up must pass the flag
        # explicitly via --build-arg (like the benchmarks' common.mk) so every
        # Dockerfile receives it.
        calls = []

        class _R:
            def __init__(self, stdout=""): self.stdout, self.returncode = stdout, 0

        def fake_run(argv, **kw):
            calls.append(argv)
            if "config" in argv and "--format" in argv:
                return _R('{"services":{"web":{"ports":[{"target":8000}]}}}')
            if "config" in argv and "--services" in argv:
                return _R("web")
            if argv[:3] == ["docker", "compose", "port"]:
                return _R("0.0.0.0:32770")
            if argv and argv[0] == "curl":
                return _R("200")                    # _wait_ready sees it up at once
            return _R("")

        import bench.xbow_runner as XR
        orig = XR.subprocess.run
        XR.subprocess.run = fake_run
        try:
            base = XR.Compose().up("/some/dir", "flag{secret-xyz}")
        finally:
            XR.subprocess.run = orig

        build = next(c for c in calls if c[:3] == ["docker", "compose", "build"])
        self.assertIn("--build-arg", build)
        self.assertIn("FLAG=flag{secret-xyz}", build)     # upper-case ARG
        self.assertIn("flag=flag{secret-xyz}", build)     # lower-case ARG
        self.assertEqual(base, "http://127.0.0.1:32770")  # resolved (host not rejected)


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
