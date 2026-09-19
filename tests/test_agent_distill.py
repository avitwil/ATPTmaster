import unittest

from modules.agent_offensive.distill import distill
from modules.agent_offensive.actions import last_json


class LastJsonTest(unittest.TestCase):
    def test_returns_last_object(self):
        self.assertEqual(last_json('noise {"a":1} tail {"b":2} end'), {"b": 2})

    def test_none_on_junk(self):
        self.assertIsNone(last_json("no json here"))
        self.assertIsNone(last_json(""))


class DistillTest(unittest.TestCase):
    def test_templatises_concrete_target_and_listener(self):
        model = ('Here is the skill:\n'
                 '{"name":"sqli-dump","applies_to":{"goal_tags":["dump"],'
                 '"service_tags":["http","mysql"]},'
                 '"steps":[{"command":["sqlmap","-u","http://10.1.1.5/item?id=1","--dump"],'
                 '"note":"id"}],"success_note":"UNION SQLi"}')
        skill = distill(goal="dump the db", transcript="...winning steps...",
                        reason_fn=lambda p: model,
                        substitutions={"10.1.1.5": "{TARGET}"},
                        provenance={"engagement": "e1"})
        self.assertEqual(skill["steps"][0]["command"][2], "http://{TARGET}/item?id=1")
        self.assertEqual(skill["provenance"]["engagement"], "e1")
        self.assertEqual(skill["applies_to"]["service_tags"], ["http", "mysql"])

    def test_none_when_model_returns_no_steps(self):
        self.assertIsNone(distill(goal="x", transcript="y",
                                  reason_fn=lambda p: '{"name":"z"}'))
        self.assertIsNone(distill(goal="x", transcript="y", reason_fn=lambda p: "junk"))

    def test_none_when_steps_is_not_a_list(self):
        # a truthy non-list `steps` (string or dict) must be rejected, not iterated
        self.assertIsNone(distill(goal="x", transcript="y",
                                  reason_fn=lambda p: '{"name":"z","steps":"x"}'))
        self.assertIsNone(distill(goal="x", transcript="y",
                                  reason_fn=lambda p: '{"name":"z","steps":{"a":1}}'))

    def test_prompt_receives_goal_and_transcript(self):
        seen = {}

        def rf(p):
            seen["p"] = p
            return '{"name":"n","steps":[{"command":["id"]}]}'

        distill(goal="GOALTEXT", transcript="TRANSCRIPTTEXT", reason_fn=rf)
        self.assertIn("GOALTEXT", seen["p"])
        self.assertIn("TRANSCRIPTTEXT", seen["p"])
