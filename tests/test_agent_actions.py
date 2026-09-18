import unittest

from modules.agent_offensive.actions import parse_action


class ActionsTest(unittest.TestCase):
    def test_json_list_command(self):
        a = parse_action('reasoning...\n{"command": ["nmap","-Pn","10.1.1.5"], "rationale":"scan"}')
        self.assertEqual(a.argv, ["nmap", "-Pn", "10.1.1.5"])
        self.assertFalse(a.done)

    def test_json_string_command_is_split(self):
        a = parse_action('{"command": "curl -s http://10.1.1.5/"}')
        self.assertEqual(a.argv, ["curl", "-s", "http://10.1.1.5/"])

    def test_last_json_wins(self):
        a = parse_action('{"command":["a"]}\nmore\n{"command":["nmap","10.1.1.5"]}')
        self.assertEqual(a.argv[0], "nmap")

    def test_done(self):
        a = parse_action('{"done": true, "rationale":"goal met"}')
        self.assertTrue(a.done)
        self.assertEqual(a.argv, [])

    def test_garbage_is_none(self):
        self.assertIsNone(parse_action("no json here"))


if __name__ == "__main__":
    unittest.main()
