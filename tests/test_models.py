"""Live model discovery per provider backend (mocked HTTP)."""
import unittest

from atpt import models


class ModelsTest(unittest.TestCase):
    def setUp(self):
        self._get = models._get_json

    def tearDown(self):
        models._get_json = self._get

    def _mock(self, payload, capture=None):
        def f(url, headers, timeout=20):
            if capture is not None:
                capture.append((url, headers))
            return payload
        models._get_json = f

    def test_openai_lists_ids_and_uses_bearer(self):
        cap = []
        self._mock({"data": [{"id": "gpt-5"}, {"id": "gpt-4o"}]}, cap)
        m, err = models.list_models({"backend": "http_api", "api": "openai", "api_key": "sk-x"})
        self.assertIsNone(err)
        self.assertEqual(m, ["gpt-5", "gpt-4o"])
        self.assertEqual(cap[0][0], "https://api.openai.com/v1/models")
        self.assertEqual(cap[0][1].get("Authorization"), "Bearer sk-x")

    def test_openai_custom_endpoint_derives_models_url(self):
        cap = []
        self._mock({"data": [{"id": "m1"}]}, cap)
        models.list_models({"backend": "http_api", "api": "openai", "api_key": "k",
                            "endpoint": "https://gw.local/v1/chat/completions"})
        self.assertEqual(cap[0][0], "https://gw.local/v1/models")

    def test_anthropic_lists_and_requires_key(self):
        cap = []
        self._mock({"data": [{"id": "claude-opus-5"}]}, cap)
        m, err = models.list_models({"backend": "http_api", "api": "anthropic", "api_key": "sk-a"})
        self.assertEqual(m, ["claude-opus-5"])
        self.assertEqual(cap[0][1].get("x-api-key"), "sk-a")
        # no key -> error, no request
        m2, err2 = models.list_models({"backend": "http_api", "api": "anthropic"})
        self.assertEqual(m2, [])
        self.assertIn("no API key", err2)

    def test_ollama_lists_tags(self):
        cap = []
        self._mock({"models": [{"name": "llama3.1"}, {"name": "qwen2"}]}, cap)
        m, err = models.list_models({"backend": "ollama"})
        self.assertEqual(m, ["llama3.1", "qwen2"])
        self.assertEqual(cap[0][0], "http://localhost:11434/api/tags")

    def test_cli_has_no_list(self):
        m, err = models.list_models({"backend": "cli", "cmd": "claude -p"})
        self.assertEqual(m, [])
        self.assertIn("CLI", err)

    def test_never_raises_on_http_error(self):
        def boom(url, headers, timeout=20):
            raise OSError("connection refused")
        models._get_json = boom
        m, err = models.list_models({"backend": "ollama"})
        self.assertEqual(m, [])
        self.assertIn("connection refused", err)
