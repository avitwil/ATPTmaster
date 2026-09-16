"""recon_wireless + recon_mobile — pure parsers + config-gated run paths."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

from atpt.module import RunContext
from atpt.registry import discover
from atpt.state import SQLiteStore


def _load(mod_id):
    spec = importlib.util.spec_from_file_location(
        f"{mod_id}_mod", Path(f"modules/{mod_id}/module.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_wifi = _load("recon_wireless")
_mob = _load("recon_mobile")

_AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:DD:EE:FF, t, t, 6, 130, OPN,  ,  , -40, 10, 0, 0.0.0.0, 8, FreeWifi, \n"
    "11:22:33:44:55:66, t, t, 1, 130, WPA2, CCMP, PSK, -50, 10, 0, 0.0.0.0, 6, Secure, \n"
)

_MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
    '<application>'
    '<activity android:name=".Public" android:exported="true"/>'
    '<service android:name=".Priv" android:exported="false"/>'
    '</application></manifest>'
)


class WirelessMobileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pd = Path(self.tmp.name)
        self.store = SQLiteStore(self.pd / "db.sqlite")
        self.mods = discover(Path("modules"), Path("."))

    def tearDown(self):
        self.store.cx.close()
        self.tmp.cleanup()

    def _ctx(self, config, dry_run=False):
        self.store.create_engagement("E", "E", {}, "s.json", "full", config)
        return RunContext(engagement=self.store.get_engagement("E"), scope={},
                          store=self.store, project_dir=self.pd, dry_run=dry_run)

    # --- wireless ---
    def test_wireless_parser_flags_open_and_wep_only(self):
        out = _wifi.parse_airodump(_AIRODUMP_CSV)
        self.assertEqual(len(out), 1)                       # only the OPN AP
        self.assertIn("FreeWifi", out[0]["title"])
        self.assertEqual(out[0]["domain"], "Wireless")

    def test_wireless_no_csv_skips(self):
        self.assertIn("recon_wireless", self.mods)
        res = self.mods["recon_wireless"].run(self._ctx({}))
        self.assertIn("no wireless CSV", res.summary)

    def test_wireless_run_parses_csv_file(self):
        p = self.pd / "cap.csv"
        p.write_text(_AIRODUMP_CSV)
        res = self.mods["recon_wireless"].run(self._ctx({"wireless": {"csv": str(p)}}))
        self.assertEqual(len(res.findings), 1)

    # --- mobile ---
    def test_mobile_parser_flags_exported_only(self):
        out = _mob.parse_manifest(_MANIFEST)
        self.assertEqual(len(out), 1)
        self.assertIn("Exported activity", out[0]["title"])
        self.assertEqual(out[0]["domain"], "Mobile")

    def test_mobile_parser_rejects_doctype_entities(self):
        # billion-laughs style manifest must be refused before parsing
        bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
                '<!ENTITY lol2 "&lol;&lol;&lol;">]>'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<application><activity android:exported="true" android:name="&lol2;"/>'
                '</application></manifest>')
        self.assertEqual(_mob.parse_manifest(bomb), [])

    def test_mobile_no_config_skips(self):
        self.assertIn("recon_mobile", self.mods)
        res = self.mods["recon_mobile"].run(self._ctx({}))
        self.assertIn("no APK/manifest", res.summary)

    def test_mobile_run_reads_manifest_path(self):
        p = self.pd / "AndroidManifest.xml"
        p.write_text(_MANIFEST)
        res = self.mods["recon_mobile"].run(self._ctx({"mobile": {"manifest": str(p)}}))
        self.assertEqual(len(res.findings), 1)
