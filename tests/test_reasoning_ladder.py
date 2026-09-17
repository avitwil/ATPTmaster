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
