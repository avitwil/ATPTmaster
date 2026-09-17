"""recon_nebula must persist a scope file (UI/demo engagements don't write one)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from atpt.module import RunContext


def _load_recon():
    p = Path("modules/recon_nebula/module.py")
    spec = importlib.util.spec_from_file_location("recon_nebula_t", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ReconNebula, mod.Manifest if hasattr(mod, "Manifest") else None


class ReconScopeTest(unittest.TestCase):
    def test_command_writes_scope_file_and_targets(self):
        from atpt.module import Manifest
        ReconNebula, _ = _load_recon()
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "recon").mkdir()
            (proj / "recon" / "recon_runner.sh").write_text("#!/bin/sh\n")
            man = Manifest(id="recon_nebula", name="Recon", phase="recon",
                           entrypoint="module:ReconNebula")
            mod = ReconNebula(man, proj)
            ctx = RunContext(engagement={"id": "thm1", "config": "{}", "scope_file": "thm1.scope.json"},
                             scope={"in_scope_cidrs": ["10.112.178.149/32"], "in_scope_domains": []},
                             store=None, project_dir=proj)
            cmd = mod._command(ctx)
            sf = proj / "var" / "thm1.scope.json"
            self.assertTrue(sf.exists())                                  # scope file written
            self.assertEqual(json.loads(sf.read_text())["in_scope_cidrs"], ["10.112.178.149/32"])
            self.assertIn(str(sf), cmd)                                   # command uses it
            self.assertIn("--target 10.112.178.149/32", cmd)             # target passed
            self.assertIn("nmap", cmd)                                    # nmap in default chain
