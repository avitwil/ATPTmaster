import unittest
from bench.actions import Action, parse_action, tool_schema_block

KNOWN = {"execute_bash", "final_answer", "http_request"}


class ParseAction(unittest.TestCase):
    def test_fenced_json(self):
        t = 'Reasoning here.\n```json\n{"thought":"scan","tool":"execute_bash","args":{"cmd":"ls"}}\n```'
        a = parse_action(t, KNOWN)
        self.assertEqual(a.tool, "execute_bash")
        self.assertEqual(a.args["cmd"], "ls")
        self.assertEqual(a.thought, "scan")

    def test_last_block_wins(self):
        t = ('```json\n{"tool":"execute_bash","args":{"cmd":"a"}}\n```\n'
             'changed my mind\n```json\n{"tool":"final_answer","args":{"flag":"F"}}\n```')
        a = parse_action(t, KNOWN)
        self.assertEqual(a.tool, "final_answer")
        self.assertEqual(a.args["flag"], "F")

    def test_bare_object_fallback(self):
        t = 'no fence: {"tool":"http_request","args":{"path":"/"}} trailing'
        a = parse_action(t, KNOWN)
        self.assertEqual(a.tool, "http_request")

    def test_unknown_tool_is_none(self):
        self.assertIsNone(parse_action('{"tool":"rm_rf","args":{}}', KNOWN))

    def test_malformed_is_none(self):
        self.assertIsNone(parse_action("no json at all", KNOWN))
        self.assertIsNone(parse_action('{"tool": "execute_bash"', KNOWN))  # unbalanced

    def test_missing_args_defaults_empty(self):
        a = parse_action('{"tool":"final_answer"}', KNOWN)
        self.assertEqual(a.args, {})


class Schema(unittest.TestCase):
    def test_schema_lists_tools(self):
        block = tool_schema_block([{"name": "execute_bash", "args": ["cmd"], "desc": "run"}])
        self.assertIn("execute_bash", block)
        self.assertIn("cmd", block)
        self.assertIn("run", block)


if __name__ == "__main__":
    unittest.main()
