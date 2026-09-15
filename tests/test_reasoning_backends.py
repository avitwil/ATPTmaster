import json
import os
import unittest

from atpt import reasoning
from atpt.reasoning import _backend_http_api, _backend_ollama, _extract_text, BACKENDS


class _CapResp:
    def __init__(self, payload): self._p = payload
    def read(self): return self._p
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _fake_urlopen(captured, payload):
    def _f(req, timeout=None):
        captured.append(req)
        return _CapResp(payload)
    return _f


class BackendsTest(unittest.TestCase):
    def test_registry_wired(self):
        self.assertEqual(set(BACKENDS), {"cli", "http_api", "ollama"})

    def test_extract_text_shapes(self):
        self.assertEqual(_extract_text({"response": "r"}), "r")
        self.assertEqual(_extract_text({"content": [{"text": "c"}]}), "c")
        self.assertEqual(
            _extract_text({"choices": [{"message": {"content": "m"}}]}), "m")

    def test_http_api_missing_key_raises(self):
        cfg = {"endpoint": "http://x", "model": "m", "key_env": "DEFINITELY_UNSET_KEY_XZ"}
        with self.assertRaises(RuntimeError):
            _backend_http_api(cfg, "hi")

    def test_ollama_parses_response(self):
        class _Resp:
            def read(self): return b'{"response": "hello"}'
            def __enter__(self): return self
            def __exit__(self, *a): return False
        orig = reasoning.urllib.request.urlopen
        reasoning.urllib.request.urlopen = lambda req, timeout=None: _Resp()
        try:
            self.assertEqual(_backend_ollama({"model": "m"}, "hi"), "hello")
        finally:
            reasoning.urllib.request.urlopen = orig

    def _run_http(self, cfg, payload):
        os.environ["ATPT_TEST_KEY"] = "sekret"
        captured = []
        orig = reasoning.urllib.request.urlopen
        reasoning.urllib.request.urlopen = _fake_urlopen(captured, payload)
        try:
            out = _backend_http_api(cfg, "hello")
        finally:
            reasoning.urllib.request.urlopen = orig
            os.environ.pop("ATPT_TEST_KEY", None)
        return out, captured[0]

    def test_http_api_anthropic_shape(self):
        cfg = {"api": "anthropic", "model": "claude-x", "key_env": "ATPT_TEST_KEY"}
        out, req = self._run_http(cfg, b'{"content": [{"type": "text", "text": "AN"}]}')
        self.assertEqual(out, "AN")
        self.assertEqual(req.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(req.headers.get("X-api-key"), "sekret")
        self.assertIsNotNone(req.headers.get("Anthropic-version"))
        self.assertIsNone(req.headers.get("Authorization"))
        body = json.loads(req.data.decode())
        self.assertEqual(body["messages"], [{"role": "user", "content": "hello"}])
        self.assertIn("max_tokens", body)
        self.assertEqual(body["model"], "claude-x")

    def test_http_api_openai_shape(self):
        cfg = {"api": "openai", "model": "gpt-x", "key_env": "ATPT_TEST_KEY"}
        out, req = self._run_http(cfg, b'{"choices": [{"message": {"content": "OA"}}]}')
        self.assertEqual(out, "OA")
        self.assertEqual(req.full_url, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(req.headers.get("Authorization"), "Bearer sekret")
        self.assertIsNone(req.headers.get("X-api-key"))
        body = json.loads(req.data.decode())
        self.assertEqual(body["messages"], [{"role": "user", "content": "hello"}])
        self.assertNotIn("prompt", body)

    def test_http_api_defaults_to_openai_and_honors_endpoint(self):
        cfg = {"model": "m", "key_env": "ATPT_TEST_KEY",
               "endpoint": "https://gw.local/v1/chat/completions"}
        out, req = self._run_http(cfg, b'{"choices": [{"message": {"content": "GW"}}]}')
        self.assertEqual(out, "GW")
        self.assertEqual(req.full_url, "https://gw.local/v1/chat/completions")
        self.assertEqual(req.headers.get("Authorization"), "Bearer sekret")
