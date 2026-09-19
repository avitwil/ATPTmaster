import unittest
from modules.agent_scope.agent import build_prompt, extract_proposed_scope


class ScopeAgentTest(unittest.TestCase):
    def test_confirm_prompt_when_typed_scope_present(self):
        p = build_prompt({"in_scope_domains": ["t.com"]}, [{"role": "user", "text": "hi"}])
        self.assertIn("already", p.lower())
        self.assertIn("t.com", p)

    def test_elicit_prompt_when_no_scope(self):
        p = build_prompt(None, [])
        self.assertIn("not", p.lower())
        self.assertIn("PROPOSED_SCOPE", p)

    def test_extract_proposed_scope(self):
        text = 'Sure. PROPOSED_SCOPE: {"in_scope_domains":["a.com"],"in_scope_cidrs":[],"out_of_scope":[]}\nApprove?'
        self.assertEqual(extract_proposed_scope(text)["in_scope_domains"], ["a.com"])

    def test_extract_none_when_absent(self):
        self.assertIsNone(extract_proposed_scope("just chatting, no proposal yet"))
