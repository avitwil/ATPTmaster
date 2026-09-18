"""bench CLI: preflight, build the ladder, run a suite, write the scoreboard."""
from __future__ import annotations
import argparse
import os
import sys

from . import ladder_brain, preflight, report


def _dump_transcripts(results, out_dir):
    """Write each episode's full transcript to out_dir/transcripts/ so a run is
    inspectable (why did it solve/fail?). Never breaks the run."""
    tdir = os.path.join(out_dir, "transcripts")
    written = []
    try:
        os.makedirs(tdir, exist_ok=True)
        for suite, eps in results.items():
            for e in eps:
                safe = "".join(c if (c.isalnum() or c in "-._") else "_"
                               for c in str(e.task_id))
                path = os.path.join(tdir, f"{suite}__{safe}.txt")
                with open(path, "w") as f:
                    f.write(e.transcript or "")
                written.append(path)
    except Exception:
        pass
    return written


def build_parser():
    p = argparse.ArgumentParser(prog="bench", description="ATPT benchmark runner")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a benchmark suite")
    r.add_argument("--suite", choices=["xbow", "autopenbench", "both"], required=True)
    r.add_argument("--smoke", type=int, default=None,
                   help="run only the first N tasks of each suite")
    r.add_argument("--primary", default="opus")
    r.add_argument("--fallback", default="deephat")
    r.add_argument("--max-steps", type=int, default=25)
    r.add_argument("--out", default="var/bench")
    r.add_argument("--dry-run", action="store_true")
    return p


def _print_plan(args, cfg):
    print("=== bench dry-run ===")
    print("suite:", args.suite, "smoke:", args.smoke, "max-steps:", args.max_steps)
    print("ladder:", " -> ".join(e["provider"] for e in cfg["ladder"]))
    for name, pc in cfg["providers"].items():
        print(f"  {name}: backend={pc['backend']} model={pc.get('model')}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    cfg = ladder_brain.build_config(args.primary, args.fallback)
    if getattr(args, "dry_run", False):
        _print_plan(args, cfg)
        return 0

    model = cfg["providers"].get("deephat", {}).get("model", "")
    need_docker = True
    fails = preflight.preflight(args.suite, model=model, need_docker=need_docker)
    if fails:
        print("Preflight failed:")
        for f in fails:
            print("  -", f)
        return 2

    from . import xbow_runner, autopenbench_runner
    brain = ladder_brain.LadderBrain(cfg, emit=lambda *a, **k: print("  ·", *a))
    results = {}
    if args.suite in ("xbow", "both"):
        chals = xbow_runner.discover_challenges(limit=args.smoke)
        results["xbow"] = xbow_runner.run_suite(chals, brain, max_steps=args.max_steps)
    if args.suite in ("autopenbench", "both"):
        tasks = autopenbench_runner.load_tasks(limit=args.smoke)
        from autopenbench.driver import PentestDriver
        results["autopenbench"] = autopenbench_runner.run_suite(
            tasks, brain, driver_factory=PentestDriver, max_steps=args.max_steps)

    jp, mp = report.write_reports(results, args.out)
    ts = _dump_transcripts(results, args.out)
    print(f"\nScoreboard: {mp}\n           {jp}")
    if ts:
        print(f"Transcripts: {os.path.join(args.out, 'transcripts')}/ ({len(ts)} files)")
    with open(mp) as f:
        print(f.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
