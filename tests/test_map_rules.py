import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "map_ptt_rules", Path("modules/map_ptt/rules.py"))
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)


class MapRulesTest(unittest.TestCase):
    def test_ssh_service_maps_to_credential_candidate(self):
        out = rules.map_assets([{"id": 1, "asset_type": "service",
                                 "value": "h:22", "service": "ssh", "port": 22}])
        self.assertEqual(len(out), 1)
        c = out[0]
        self.assertEqual(c["asset_id"], 1)
        self.assertEqual(c["domain"], "Infra")
        self.assertEqual(c["owasp"], "A07")
        self.assertEqual(c["status"], "candidate")
        self.assertEqual(c["source_tool"], "map_ptt")
        self.assertEqual(c["evidence"]["provenance"], "rules")

    def test_data_service_is_high_severity(self):
        out = rules.map_assets([{"id": 2, "asset_type": "service",
                                 "value": "h:6379", "service": "redis"}])
        self.assertTrue(any(c["severity"] == "high" for c in out))

    def test_sensitive_web_path(self):
        out = rules.map_assets([{"id": 3, "asset_type": "web_path",
                                 "value": "http://h/admin", "url": "http://h/admin"}])
        self.assertTrue(any("path" in c["title"].lower() for c in out))

    def test_dedupe_on_asset_and_title(self):
        a = {"id": 4, "asset_type": "service", "value": "h:22",
             "service": "ssh", "port": 22}
        out = rules.map_assets([a, dict(a)])
        titles = [c["title"] for c in out if c["asset_id"] == 4]
        self.assertEqual(len(titles), len(set(titles)))

    def test_sorted_by_priority_desc(self):
        out = rules.map_assets([
            {"id": 5, "asset_type": "service", "value": "h:6379", "service": "redis"},
            {"id": 6, "asset_type": "web_endpoint", "value": "http://h", "url": "http://h"},
        ])
        prios = [c["evidence"]["priority"] for c in out]
        self.assertEqual(prios, sorted(prios, reverse=True))

    def test_web_known_tech_decodes_json_encoded_tech_string(self):
        # store.list_assets returns "tech" as a JSON-encoded string (because
        # upsert_asset JSON-encodes list values on write), e.g. '["nginx","php"]'.
        # _rule_web_known_tech must decode it into one candidate per tech,
        # not mangle it into a single candidate over the raw string.
        out = rules.map_assets([{"id": 7, "asset_type": "web_endpoint",
                                 "value": "http://h", "url": "http://h",
                                 "tech": '["nginx", "php"]'}])
        known_tech = [c for c in out if c["evidence"]["rule"] == "known_tech"]
        self.assertEqual(len(known_tech), 2)
        titles = {c["title"] for c in known_tech}
        self.assertIn("Known-CVE candidate (nginx)", titles)
        self.assertIn("Known-CVE candidate (php)", titles)


if __name__ == "__main__":
    unittest.main()
