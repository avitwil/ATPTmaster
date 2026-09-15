"""atpt — command-line driver for the ATPTmaster core."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

from .engine import Orchestrator
from .registry import discover
from .state import SQLiteStore


def _project_dir() -> Path:
    return Path(os.environ.get("ATPT_HOME", os.getcwd())).resolve()


def _bootstrap():
    pd = _project_dir()
    if str(pd) not in sys.path:
        sys.path.insert(0, str(pd))          # so modules can `import atpt`
    store = SQLiteStore(pd / "var" / "atpt.db")
    modules = discover(pd / "modules", pd)
    return pd, store, modules


def cmd_init(args):
    pd, store, _ = _bootstrap()
    scope_path = Path(args.scope).resolve()
    scope = json.loads(scope_path.read_text())
    eid = args.engagement or scope.get("engagement")
    if not eid:
        print("error: no engagement id (--engagement or scope.engagement)", file=sys.stderr)
        return 2
    cfg = {"recon_tools": args.recon_tools, "rate": args.rate}
    store.create_engagement(eid, args.name or eid, scope, scope_path, args.mode, cfg)
    store.add_event(eid, "scope", None, "info", "engagement_init",
                    f"engagement '{eid}' initialized (mode={args.mode})", None)
    print(f"initialized engagement '{eid}'  mode={args.mode}  scope={scope_path}")
    return 0


def cmd_modules(args):
    _, _, modules = _bootstrap()
    if not modules:
        print("no modules found under modules/")
        return 0
    print(f"{'ID':22} {'PHASE':9} {'INTRUSIVE':9} EXTRACTED_FROM")
    for m in sorted(modules.values(), key=lambda x: x.manifest.id):
        man = m.manifest
        print(f"{man.id:22} {man.phase:9} {str(man.intrusive):9} {man.extracted_from}")
    return 0


def _load_eng(store, eid):
    eng = store.get_engagement(eid)
    if not eng:
        print(f"error: no engagement '{eid}' (run: atpt init)", file=sys.stderr)
    return eng


def cmd_plan(args):
    _, store, modules = _bootstrap()
    eng = _load_eng(store, args.engagement)
    if not eng:
        return 2
    mode = args.mode or eng["mode"]
    orch = Orchestrator(store, modules, _project_dir())
    rows = orch.plan(eng, mode)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"plan for '{eng['id']}' (mode={mode}) — {len(rows)} module(s) pending:")
    for r in rows:
        tag = "  [GATED: needs approval]" if r["gated"] else ("  [intrusive]" if r["intrusive"] else "")
        print(f"  {r['phase']:9} {r['id']}{tag}")
    if not rows:
        print("  (nothing pending — all satisfied or blocked on missing inputs)")
    return 0


def cmd_run(args):
    _, store, modules = _bootstrap()
    eng = _load_eng(store, args.engagement)
    if not eng:
        return 2
    mode = args.mode or eng["mode"]
    orch = Orchestrator(store, modules, _project_dir())
    res = orch.run(eng, mode, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    dry = " (dry-run)" if args.dry_run else ""
    print(f"ran mode={mode}{dry}: executed={res['executed'] or '[]'}")
    if res["gated_on"]:
        print(f"  PAUSED before intrusive module '{res['gated_on']}' — approve with:")
        print(f"    atpt approve {res['gated_on']} --engagement {eng['id']}")
    return 0


def cmd_status(args):
    _, store, _ = _bootstrap()
    eng = _load_eng(store, args.engagement)
    if not eng:
        return 2
    eid = eng["id"]
    data = {
        "engagement": eid, "mode": eng["mode"], "status": eng["status"],
        "assets": store.count_assets(eid),
        "asset_types": store.asset_type_counts(eid),
        "findings": store.count_findings(eid),
        "validated": store.count_findings(eid, status="validated"),
        "pending_approvals": store.pending_approvals(eid),
    }
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(f"engagement '{eid}'  mode={eng['mode']}  status={eng['status']}")
    print(f"  assets={data['assets']}  findings={data['findings']}  validated={data['validated']}")
    for t, c in data["asset_types"]:
        print(f"    - {t}: {c}")
    if data["pending_approvals"]:
        print("  pending approvals:")
        for a in data["pending_approvals"]:
            print(f"    - {a['module']} ({a['phase']}): {a['reason']}")
    print("  recent events:")
    for e in store.recent_events(eid, args.events):
        print(f"    [{e['ts']}] {e['level']:5} {e['kind']}: {e['message']}")
    return 0


def cmd_approve(args):
    _, store, _ = _bootstrap()
    eng = _load_eng(store, args.engagement)
    if not eng:
        return 2
    decision = "denied" if args.deny else "approved"
    store.resolve_approval(eng["id"], args.module, decision)
    store.add_event(eng["id"], None, args.module, "info", "approval_resolved",
                    f"module '{args.module}' {decision}", None)
    print(f"module '{args.module}' {decision} for '{eng['id']}'")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="atpt", description="ATPTmaster core driver")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="create/refresh an engagement from a scope file")
    pi.add_argument("--scope", required=True)
    pi.add_argument("--engagement")
    pi.add_argument("--name")
    pi.add_argument("--mode", choices=["step", "semi", "full"], default="step")
    pi.add_argument("--recon-tools", dest="recon_tools", default="subfinder,naabu,httpx")
    pi.add_argument("--rate", type=int, default=150)
    pi.set_defaults(func=cmd_init)

    pm = sub.add_parser("modules", help="list discovered modules")
    pm.set_defaults(func=cmd_modules)

    pp = sub.add_parser("plan", help="show pending modules for a mode")
    pp.add_argument("--engagement", required=True)
    pp.add_argument("--mode", choices=["step", "semi", "full"])
    pp.add_argument("--json", action="store_true")
    pp.set_defaults(func=cmd_plan)

    pr = sub.add_parser("run", help="execute pending modules per mode")
    pr.add_argument("--engagement", required=True)
    pr.add_argument("--mode", choices=["step", "semi", "full"])
    pr.add_argument("--dry-run", action="store_true")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=cmd_run)

    ps = sub.add_parser("status", help="engagement state summary")
    ps.add_argument("--engagement", required=True)
    ps.add_argument("--events", type=int, default=10)
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_status)

    pa = sub.add_parser("approve", help="approve (or --deny) a gated module")
    pa.add_argument("module")
    pa.add_argument("--engagement", required=True)
    pa.add_argument("--deny", action="store_true")
    pa.set_defaults(func=cmd_approve)

    args = p.parse_args(argv)
    return args.func(args)
