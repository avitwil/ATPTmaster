"""Model-based ladder: per-entry provider/model/effort, with preference fallback."""
import json
import os
import unittest

from atpt import reasoning
from atpt.reasoning import ReasoningLadder, _backend_http_api


class _Cap:
    def __init__(self, payload): self._p = payload
    def read(self): return self._p
    def __enter__(self): return self
    def __exit__(self, *a): return False


class LadderTest(unittest.TestCase):
    def _providers(self):
        return {"oa": {"backend": "http_api", "api": "openai", "model": "gpt-default", "api_key": "k"},
                "loc": {"backend": "ollama", "model": "llama3.1"}}

    def test_ladder_entries_override_model_and_order(self):
        seen = []

        def fake_oa(cfg, prompt):
            seen.append(("oa", cfg.get("model"), cfg.get("effort")))
            return "ANS"
        orig = reasoning.BACKENDS["http_api"]
        reasoning.BACKENDS["http_api"] = fake_oa
        try:
            lad = ReasoningLadder({"providers": self._providers(),
                                   "ladder": [{"provider": "oa", "model": "gpt-5", "effort": "high"}]})
            res = lad.reason("hi", "map")
        finally:
            reasoning.BACKENDS["http_api"] = orig
        self.assertEqual(res.text, "ANS")
        self.assertEqual(seen[0], ("oa", "gpt-5", "high"))   # model + effort applied

    def test_falls_back_to_preference_without_ladder(self):
        def fake_oa(cfg, prompt): return "P"
        orig = reasoning.BACKENDS["http_api"]
        reasoning.BACKENDS["http_api"] = fake_oa
        try:
            lad = ReasoningLadder({"providers": self._providers(), "preference": ["oa"]})
            self.assertEqual(lad.reason("hi", "map").provider, "oa")
        finally:
            reasoning.BACKENDS["http_api"] = orig

    def test_effort_sent_as_reasoning_effort_for_openai(self):
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return _Cap(b'{"choices":[{"message":{"content":"x"}}]}')
        orig = reasoning.urllib.request.urlopen
        reasoning.urllib.request.urlopen = fake_urlopen
        try:
            _backend_http_api({"api": "openai", "model": "gpt-5", "api_key": "k", "effort": "high"}, "hi")
        finally:
            reasoning.urllib.request.urlopen = orig
        body = json.loads(captured[0].data.decode())
        self.assertEqual(body.get("reasoning_effort"), "high")

    def test_cli_backend_appends_model_flag(self):
        seen = {}

        def fake_run(argv, capture_output=True, text=True, timeout=None):
            seen["argv"] = argv
            class R: returncode, stdout, stderr = 0, "ok", ""
            return R()
        orig = reasoning.subprocess.run
        reasoning.subprocess.run = fake_run
        try:
            from atpt.reasoning import _backend_cli
            _backend_cli({"cmd": "/usr/bin/claude -p", "model": "sonnet", "model_flag": "--model"}, "hi")
        finally:
            reasoning.subprocess.run = orig
        self.assertEqual(seen["argv"][:5], ["/usr/bin/claude", "-p", "--model", "sonnet", "hi"])

    def test_no_effort_no_param(self):
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return _Cap(b'{"choices":[{"message":{"content":"x"}}]}')
        orig = reasoning.urllib.request.urlopen
        reasoning.urllib.request.urlopen = fake_urlopen
        try:
            _backend_http_api({"api": "openai", "model": "gpt-5", "api_key": "k"}, "hi")
        finally:
            reasoning.urllib.request.urlopen = orig
        self.assertNotIn("reasoning_effort", json.loads(captured[0].data.decode()))


ROLE_CFG = {
    "providers": {"p1": {"backend": "fake"}, "p2": {"backend": "fake"}},
    "ladder": [{"provider": "p1"}],
    "roles": {"report": {"ladder": [{"provider": "p2"}]}},
}


class RoleLadderTest(unittest.TestCase):
    def setUp(self):
        self._saved = dict(reasoning.BACKENDS)
        reasoning.BACKENDS.clear()
        reasoning.BACKENDS["fake"] = lambda cfg, p: f"OK:{cfg.get('_who','?')}"

    def tearDown(self):
        reasoning.BACKENDS.clear(); reasoning.BACKENDS.update(self._saved)

    def test_role_override_uses_own_ladder(self):
        # tag each provider so we can see which one answered
        reasoning.BACKENDS["fake"] = lambda cfg, p: "ANS"
        L = ReasoningLadder(ROLE_CFG)
        self.assertEqual(L.reason("hi", "report", role="report").provider, "p2")

    def test_role_without_override_uses_global(self):
        self.assertEqual(ReasoningLadder(ROLE_CFG).reason("hi", "map", role="map").provider, "p1")

    def test_unknown_role_falls_back_to_global(self):
        self.assertEqual(ReasoningLadder(ROLE_CFG).reason("hi", "map", role="bogus").provider, "p1")

    def test_no_roles_key_is_global(self):
        cfg = {"providers": {"p1": {"backend": "fake"}}, "ladder": [{"provider": "p1"}]}
        self.assertEqual(ReasoningLadder(cfg).reason("hi", "map").provider, "p1")
