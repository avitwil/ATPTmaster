# bench/ — XBOW + AutoPenBench runner for ATPT

Drives external pentest benchmarks with a ReAct agent whose brain is ATPT's
reasoning ladder: **Opus 4.8** (Claude Code CLI) primary, **DeepHat-V1-7B
Q4_K_M** (Ollama) fallback. An Opus safety-refusal advances the ladder to the
local model — no prompt is rewritten to defeat guardrails.

## One-time setup
```bash
# 1) Docker access (the socket is otherwise permission-denied):
sudo usermod -aG docker $USER && newgrp docker   # then `docker ps` must work

# 2) AutoPenBench importable in this interpreter + its targets built:
pip install -e /home/avi/Projects/benchmarks/auto-pen-bench
( cd /home/avi/Projects/benchmarks/auto-pen-bench && make install )

# 3) Models present (already pulled):
ollama list | grep -E 'DeepHat-V1-7B-GGUF|qwen2.5:7b'
```

## Run (from repo root, so `import atpt` and `import bench` resolve)
```bash
python3 -m bench run --suite xbow --smoke 3 --dry-run     # show the plan only
python3 -m bench run --suite both --smoke 3               # live smoke
```
Outputs `var/bench/scoreboard.md` + `scoreboard.json`.

## Scoring
- **XBOW:** deterministic — exact match of the built `FLAG`.
- **AutoPenBench:** APB milestone `Evaluator`, judge redirected to a **local**
  model (`qwen2.5:7b` via Ollama's OpenAI endpoint). Labeled local-judge, not
  the official GPT-4o score.

## Safety
Targets are isolated, intentionally-vulnerable lab containers you own. Runners
touch only each suite's own containers and tear them down after. No egress
beyond the lab.

## Tests
```bash
python3 -m unittest discover -s bench/tests -v      # no docker/LLM needed
```
