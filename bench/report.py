"""Aggregate episodes into a JSON record + a Markdown scoreboard."""
from __future__ import annotations
from collections import Counter
from dataclasses import asdict
import json
import os
import time


def summarize(episodes: list, suite: str) -> dict:
    steps = Counter()
    for e in episodes:
        steps.update(e.providers)
    return {
        "suite": suite,
        "solved": sum(1 for e in episodes if e.solved),
        "total": len(episodes),
        "provider_steps": dict(steps),
    }


def _episode_row(e) -> dict:
    prov = Counter(e.providers)
    return {"task": e.task_id, "solved": e.solved, "steps": e.steps,
            "providers": dict(prov), "stop_reason": e.stop_reason,
            "wall_s": round(e.wall_s, 1)}


def write_reports(results: dict, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    record = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"), "suites": {}}
    md = ["# Benchmark scoreboard", "",
          f"_Generated {record['generated']}_", ""]
    for suite, eps in results.items():
        summary = summarize(eps, suite)
        record["suites"][suite] = {"summary": summary,
                                   "episodes": [_episode_row(e) for e in eps]}
        share = ", ".join(f"{k}×{v}" for k, v in summary["provider_steps"].items())
        md += [f"## {suite}",
               f"**Solved {summary['solved']}/{summary['total']}** · provider steps: {share or 'none'}",
               "", "| task | solved | steps | providers | stop | wall_s |",
               "|---|---|---|---|---|---|"]
        for r in record["suites"][suite]["episodes"]:
            p = ", ".join(f"{k}×{v}" for k, v in r["providers"].items())
            md.append(f"| {r['task']} | {'✓' if r['solved'] else '✗'} | "
                      f"{r['steps']} | {p} | {r['stop_reason']} | {r['wall_s']} |")
        md.append("")
    json_path = os.path.join(out_dir, "scoreboard.json")
    md_path = os.path.join(out_dir, "scoreboard.md")
    with open(json_path, "w") as f:
        json.dump(record, f, indent=2)
    with open(md_path, "w") as f:
        f.write("\n".join(md))
    return json_path, md_path
