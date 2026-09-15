import types
import unittest

from atpt import reasoning
from atpt.reasoning import _backend_http_api, _backend_ollama, _extract_text, BACKENDS


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
