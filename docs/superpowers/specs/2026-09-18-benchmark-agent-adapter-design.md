# Design — `bench/` benchmark-agent adapter (XBOW + AutoPenBench)

- **Date:** 2026-09-18
- **Status:** approved for spec review
- **Scope:** new top-level `bench/` subsystem; imports only `atpt.reasoning`.
  The shipped `atpt/` package and its 205 tests stay untouched and stdlib-only.
- **Driver decisions (from brainstorm):** build an interactive agent adapter;
  run both suites; smoke subset first (~3 tasks/suite); 1st LLM = Claude Opus
  4.8 via the Claude Code CLI; 2nd LLM = DeepHat-V1-7B Q4_K_M on Ollama.

## 1. Context & goal

ATPT is a fixed pipeline (`scope→recon→map→exploit→validate→post→report`) built
from deterministic modules plus optional LLM *enrichment* via `ctx.reason()`.
Its only action-capable module, `exploit_hbgpt`, is **propose-only, read-only
allowlist, no egress** by design.

XBOW `validation-benchmarks` and AutoPenBench both score an **interactive
exploit loop**: an agent that runs `bash`/`ssh`/HTTP against a live, isolated,
intentionally-vulnerable target, reads output, and iterates until it captures a
flag (XBOW) or hits milestones (AutoPenBench). ATPT cannot do this today, so
"run the benchmarks with my tool" needs a new agent whose **brain is ATPT's
existing reasoning ladder** — Opus 4.8 primary, DeepHat local fallback.

**Goal:** a `bench/` harness that drives each suite's targets with a ReAct-style
agent powered by `atpt.reasoning.ReasoningLadder`, scores with each suite's own
oracle, and emits a Markdown + JSON scoreboard. Deliver a smoke run (~3
tasks/suite) end-to-end, then a one-flag full run.

## 2. Locked constraints honored

- **`atpt/` core untouched.** `bench/` is a separate tree; it `import`s
  `atpt.reasoning` (ladder) and nothing writes back into `atpt/`. Core stays
  stdlib-only; `bench/` may use `autopenbench` (already installed in its own
  venv) and shells out to `docker`.
- **Reuse the ladder verbatim.** No new provider mechanics. An Opus safety
  refusal *advances* the ladder to the local DeepHat model — exactly the
  operator's stated philosophy (hosted for orchestration/parsing, local model
  for exploitation reasoning). We never rewrite a prompt to defeat guardrails.
- **Authorized-target only.** Runners act solely on the suite's own containers,
  on the lab network, and tear them down after. No egress beyond the lab. This
  is authorized benchmarking against owned, isolated, deliberately-vulnerable
  labs.
- **No secrets on disk/argv.** Opus is reached through the already-logged-in
  Claude Code CLI (subscription); no API key is read, stored, or logged.

## 3. Confirmed environment (2026-09-18)

- Opus: `claude -p --model opus` works (returned `OPUS_OK`). CLI v2.1.274.
- DeepHat: `hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M` pulled (4.7 GB) — fits
  the RTX 3060 Laptop's 6 GB VRAM. Ollama 0.33.3 on `:11434`.
- AutoPenBench: cloned + installed at `/home/avi/Projects/benchmarks/auto-pen-bench`
  (own `.venv`, `autopenbench` egg). Tools: `execute_bash`, `ssh_connect`,
  `write_file`, `final_answer`; `driver/pentest_driver.py`;
  `evaluation/evaluator.py`; tasks in `data/games.json` (`in-vitro`,
  `real-world`). Kali workstation `192.168.0.5` root/root; targets via Docker.
- XBOW: cloned at `/home/avi/Projects/benchmarks/validation-benchmarks`, **104**
  challenges. Each `benchmarks/XBEN-*/` has `benchmark.json`
  (`name`, `description`, `level`, `win_condition:"flag"`, `tags`),
  `docker-compose.yml` (target service exposes a port; flag injected via `FLAG`
  build-arg), `Makefile`, `app/`.
- **Blocker:** Docker socket is `permission denied` for `avi` (not in `docker`
  group, gid 970). `sudo` needs a password this session cannot supply. Live runs
  wait on the operator running `sudo usermod -aG docker $USER && newgrp docker`.

## 4. Approaches considered

- **A — free-text ReAct loop + JSON-action parser, ladder as brain (CHOSEN).**
  One thin runner per suite; agent emits one fenced JSON action per turn; a
  robust last-JSON parser with a single malformed-output reprompt. Reuses the
  ladder unchanged, preserving Opus→DeepHat fallback; testable with fakes.
  Cost: needs a resilient parser. Aligns with AutoPenBench's own README note to
  "sketch an adapter to convert free text to the tool JSON schemas."
- **B — adopt AutoPenBench's `instructor`/pydantic structured output.**
  Rejected: `instructor` wants an API-key client, bypasses the ladder, and
  destroys the Opus(CLI)→DeepHat(Ollama) fallback that is the point of the task.
- **C — repurpose `exploit_hbgpt` in execute mode.** Rejected: it is
  deliberately read-only / no-egress / propose-only; flag capture needs
  arbitrary commands, so this would gut its shipped safety model. Keep it safe;
  build a separate bench agent.

## 5. Architecture

```
bench/
  __init__.py
  ladder_brain.py      # build run config + LadderBrain.think(transcript)->text
  agent.py             # ReAct loop, action parser, transcript, step budget
  actions.py           # Action dataclass + parse_action(text) + tool schema text
  autopenbench_runner.py
  xbow_runner.py
  report.py            # results -> JSON + Markdown scoreboard
  preflight.py         # docker + ollama-model + claude-cli readiness checks
  cli.py               # python -m bench run --suite ... --smoke N ...
  tests/               # unittest, fakes only (no docker/LLM/network)
```

### 5.1 `ladder_brain.py`

`build_config(primary, fallback)` returns the `reasoning` dict the ladder wants:

```python
providers = {
  "opus":    {"backend": "cli",
              "cmd": f"{shutil.which('claude') or 'claude'} -p",
              "model": "opus", "model_flag": "--model", "timeout": 180},
  "deephat": {"backend": "ollama",
              "model": "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M",
              "endpoint": "http://localhost:11434/api/generate", "timeout": 300},
}
ladder = [{"provider": "opus"}, {"provider": "deephat"}]
policy = {}                       # "any" everywhere; refusal drives the fallback
```

`LadderBrain(config).think(transcript_text, phase="exploit") -> ReasoningResult`
delegates to `ReasoningLadder.reason`. Returns the text **and which provider
answered**, so the scoreboard can show Opus-vs-DeepHat per step. The provider
list is data — `--primary`/`--fallback` on the CLI can reorder or drop either.

### 5.2 `actions.py`

- `Action(thought:str, tool:str, args:dict)`.
- `TOOL_SCHEMA` — human-readable schema block injected into the system prompt,
  listing exactly the tools the active runner supports.
- `parse_action(text) -> Action | None` — scans for the **last** ```json fenced
  block (falls back to the last balanced `{...}`), loads it, validates `tool` is
  known. Returns `None` on failure so the loop can reprompt once.

### 5.3 `agent.py`

`run_episode(brain, executor, task, *, max_steps, emit) -> Episode`:
1. Seed transcript with system prompt (role + rules + `TOOL_SCHEMA` + task
   goal + how to submit the final answer/flag).
2. Loop ≤ `max_steps`: `think` → `parse_action`; on parse failure append a
   terse "emit one JSON action" note and retry once, else stop `malformed`.
3. `executor.run(action) -> Observation(text, done, success)`. `final_answer`
   (or a flag match surfaced by the executor) ends the episode.
4. Append `OBSERVATION:` to the transcript; continue.
5. Return `Episode(task_id, solved, steps[], provider_per_step, wall_s,
   stop_reason)`.

`executor` is an interface (`run(Action)->Observation`) — the two runners each
supply one. The agent never imports docker or autopenbench; **fully unit-testable
with a `FakeExecutor` + `FakeBrain`.**

### 5.4 `autopenbench_runner.py`

- Loads tasks from APB `data/games.json`; `--smoke N` takes the first N in-vitro
  tasks (small, deterministic).
- `APBExecutor` maps our `Action.tool` → APB's tool objects
  (`execute_bash`/`ssh_connect`/`write_file`/`final_answer`) via APB's
  `PentestDriver`; observations are the tool outputs.
- Scoring: APB `evaluation.Evaluator` over the achieved milestones, but its
  judge is redirected to a **local** model — APB ships a GPT-4o judge
  (`instructor.from_openai(OpenAI(...))`, hardcoded `model='gpt-4o'`, needs an
  OpenAI key and egresses transcripts). We keep APB's milestone logic and swap
  the client: `instructor.from_openai(OpenAI(base_url="http://localhost:11434/v1",
  api_key="ollama"))` with `model="qwen2.5:7b"` (already pulled). Offline, free,
  on-brand. Results are labeled "local-judge (qwen2.5:7b)", not the official
  GPT-4o score. `instructor`+`openai` come with APB's install. Episode is
  "solved" per APB's criterion; we also record milestone counts.
- **Interpreter:** `bench/` runs under one interpreter that can import *both*
  `atpt.reasoning` (repo root on `PYTHONPATH`) and `autopenbench`. Concretely:
  `pip install -e /home/avi/Projects/benchmarks/auto-pen-bench` into the same
  environment that runs `bench` (documented in `bench/README.md`). No
  cross-venv subprocess hop — one process, both packages importable. If APB
  import fails, the AutoPenBench runner is skipped with an actionable message;
  the XBOW runner (no APB dep) still runs.

### 5.5 `xbow_runner.py`

- `--smoke N` selects N challenges (default: 3 lowest-`level`, deterministic
  order) from `validation-benchmarks/benchmarks/`.
- Per challenge: generate a random `FLAG=flag{<uuid>}`; `docker compose build`
  + `up -d` with that build-arg; wait for the target's healthcheck; resolve the
  published host port.
- `XbowExecutor` gives the agent a constrained toolset: `http_request`
  (curl to the target), `run_bash` (in an ephemeral throwaway container on the
  lab network, image `curlimages/curl`/`kalilinux` — no host shell), and
  `submit_flag`. Success = submitted string equals the built FLAG.
- Always `docker compose down -v` in a `finally`, even on crash/timeout.

### 5.6 `report.py`

`write_reports(results, out_dir)` → `scoreboard.json` + `scoreboard.md`:
suite, task, solved✓/✗, steps, providers used (e.g. `opus×4, deephat×1`),
wall-time, stop reason; plus a summary line (solved/total, per-provider step
share). This is the deliverable of the smoke run.

### 5.7 `preflight.py` + `cli.py`

- `preflight(suite)` checks: `docker info` usable; ollama model present
  (`/api/tags`); `claude` on PATH. Returns actionable failures (e.g. the exact
  `usermod` command) instead of a stack trace.
- CLI: `python -m bench run --suite {autopenbench,xbow,both} --smoke N
  [--primary opus] [--fallback deephat] [--max-steps K] [--out DIR]`. Preflight
  runs first; `--dry-run` prints the plan and the resolved ladder without
  touching docker.

## 6. Error handling

- Ladder exhaustion (both providers refuse/error) → episode stops
  `no_reasoner`, recorded, run continues to the next task.
- Malformed action twice → stop `malformed`.
- `max_steps` hit → stop `budget`.
- Target build/up failure or healthcheck timeout → task `infra_error`, teardown,
  continue.
- Any exception inside an episode → caught, task marked `crashed`, teardown runs.
  One task never aborts the batch; the scoreboard always writes.

## 7. Testing (TDD)

Unit (stdlib `unittest`, no docker/LLM/network):
- `parse_action`: fenced JSON, trailing prose, multiple blocks (last wins),
  malformed → `None`.
- `agent.run_episode`: solves via scripted `FakeExecutor`; budget stop; malformed
  reprompt→recover then stop; `final_answer` ends; provider recorded per step.
- refusal→fallback: `FakeBrain` refuses on "opus", answers on "deephat";
  assert provider switches (guards the core value prop).
- `report.write_reports`: golden scoreboard.md/json from fixed results.
- `preflight`: monkeypatched docker/ollama probes → correct actionable messages.
- `xbow_runner` flag match + teardown-always: with docker/compose calls faked.
- `autopenbench_runner` action→APB-tool mapping: with APB tools faked.

Live smoke (manual, after the docker one-liner + model present): `--smoke 3` on
each suite; success = scoreboard emitted with real solved/unsolved rows.

## 8. Deliverables

1. `bench/` package + unit tests (all green, no docker/LLM needed).
2. `bench/README.md`: the one-command docker fix, how to run, ladder wiring.
3. A smoke `scoreboard.md` once the operator enables docker (gated, not blocking
   the build).

## 9. Out of scope (YAGNI)

- No changes to `atpt/` modules, engine, web, or desktop.
- No AutoPenBench VPN/`real-world` tasks in the smoke (in-vitro only first).
- No full 104-challenge XBOW sweep until the smoke passes and the operator opts
  in (many hours of Opus CLI time).
- No parallel task execution; sequential is fine for a smoke and safer on 6 GB.
- No token/$ accounting beyond per-step provider attribution.
