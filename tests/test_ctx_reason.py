import unittest
from pathlib import Path

from atpt.module import RunContext
from atpt.reasoning import ReasoningLadder, ReasoningResult


class _FakeLadder:
    def __init__(self, result):
        self._result = result
        self.seen = None

    def reason(self, prompt, phase, role=None):
        self.seen = (phase, role)
        return self._result


class CtxReasonTest(unittest.TestCase):
    def _ctx(self, reasoner):
        return RunContext(engagement={"id": "E"}, scope={}, store=None,
                          project_dir=Path("."), dry_run=False, reasoner=reasoner)

    def test_reason_returns_text_when_ladder_answers(self):
        ctx = self._ctx(_FakeLadder(ReasoningResult(text="ANS", provider="p1")))
        self.assertEqual(ctx.reason("hi", "map"), "ANS")

    def test_reason_none_when_ladder_exhausted(self):
        ctx = self._ctx(_FakeLadder(None))
        self.assertIsNone(ctx.reason("hi", "map"))

    def test_reason_none_when_no_reasoner(self):
        ctx = self._ctx(None)
        self.assertIsNone(ctx.reason("hi", "map"))

    def test_reason_forwards_role(self):
        lad = _FakeLadder(ReasoningResult(text="ANS", provider="p1"))
        ctx = self._ctx(lad)
        self.assertEqual(ctx.reason("hi", "report", role="report"), "ANS")
        self.assertEqual(lad.seen, ("report", "report"))
