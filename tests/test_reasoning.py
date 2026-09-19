import unittest

from atpt import reasoning
from atpt.reasoning import ReasoningLadder, _is_refusal


CFG = {
    "providers": {
        "p1": {"backend": "fake"},
        "p2": {"backend": "fake"},
        "local": {"backend": "ollama"},
    },
    "preference": ["p1", "p2", "local"],
    "policy": {"map": "any", "secret": "local_only"},
}


class ReasoningLadderTest(unittest.TestCase):
    def setUp(self):
        self._saved = dict(reasoning.BACKENDS)

    def tearDown(self):
        reasoning.BACKENDS.clear()
        reasoning.BACKENDS.update(self._saved)

    def _install(self, fake, ollama=None):
        reasoning.BACKENDS.clear()
        reasoning.BACKENDS["fake"] = fake
        reasoning.BACKENDS["ollama"] = ollama or (lambda cfg, p: "OLLAMA-OK")

    def test_first_ok_wins(self):
        self._install(lambda cfg, p: "OK")
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "OK")
        self.assertEqual(res.provider, "p1")

    def test_refusal_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            return "I can't help with that." if len(calls) == 1 else "SECOND-OK"
        self._install(fake)
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "SECOND-OK")
        self.assertEqual(res.provider, "p2")

    def test_error_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return "RECOVERED"
        self._install(fake)
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "RECOVERED")

    def test_exhausted_returns_none(self):
        self._install(lambda cfg, p: "I cannot assist",
                      ollama=lambda cfg, p: "against my guidelines")
        self.assertIsNone(ReasoningLadder(CFG).reason("hi", "map"))

    def test_policy_local_only_skips_hosted(self):
        self._install(lambda cfg, p: "HOSTED", ollama=lambda cfg, p: "LOCAL")
        res = ReasoningLadder(CFG).reason("hi", "secret")
        self.assertEqual(res.text, "LOCAL")
        self.assertEqual(res.provider, "local")

    def test_empty_config_returns_none(self):
        self.assertIsNone(ReasoningLadder(None).reason("hi", "map"))

    def test_is_refusal(self):
        self.assertTrue(_is_refusal(""))
        self.assertTrue(_is_refusal("I'm unable to help"))
        self.assertFalse(_is_refusal("Sure, here are the findings"))

    def test_error_as_text_with_exit0_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            return "Model unavailable — you are rate-limited. Try again later." \
                if len(calls) == 1 else "RECOVERED"
        self._install(fake)
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "RECOVERED")
        self.assertEqual(res.provider, "p2")

    def test_json_error_envelope_advances(self):
        calls = []
        def fake(cfg, p):
            calls.append(1)
            return '{"error":{"message":"insufficient_quota"}}' \
                if len(calls) == 1 else "RECOVERED"
        self._install(fake)
        self.assertEqual(ReasoningLadder(CFG).reason("hi", "map").text, "RECOVERED")

    def test_valid_short_answer_is_not_an_error(self):
        self._install(lambda cfg, p: "22/tcp open ssh")
        res = ReasoningLadder(CFG).reason("hi", "map")
        self.assertEqual(res.text, "22/tcp open ssh")
        self.assertEqual(res.provider, "p1")

    def test_long_answer_containing_marker_is_not_an_error(self):
        # A real finding legitimately mentions "rate limit" — a long response must
        # never be discarded as error-shaped.
        long = "Finding: the login endpoint has no rate limiting, so credential " \
               "stuffing is possible. " + ("Details. " * 40)
        self._install(lambda cfg, p: long)
        self.assertEqual(ReasoningLadder(CFG).reason("hi", "map").text, long)
