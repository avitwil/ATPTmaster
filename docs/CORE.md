# ATPTmaster Core

A modular, **orchestrator-agnostic** pentest engine. It runs standalone via the
`atpt` CLI; N8N (or any driver) plugs in later by calling that CLI and reading
its events. Core is **stdlib-only** (SQLite state) so it installs on any Kali box
with no server to stand up.

```
atpt/                  core package (stdlib only)
  module.py            Manifest + Module base + RunContext  (the contract)
  registry.py          discovers modules/*/module.json
  state.py             SQLiteStore (State Tree; Postgres adapter drops in here)
  engine.py            Orchestrator: phase walk + run modes + approval gating
  cli.py               atpt init | modules | plan | run | status | approve
modules/<id>/          drop-in capabilities (extracted from the vendored tools)
  module.json          manifest
  module.py            Module subclass
```

## Phases
`scope → recon → map → exploit → validate → post → report`
Modules declare a `phase`, what they `consume` (`target`/`asset`/`finding`/
`validated_finding`) and `provide`. The engine only runs a module when its inputs
exist, so the pipeline self-sequences.

## Run modes
| Mode | Behavior |
|---|---|
| `step` | Run exactly one runnable module, then stop. Human drives each step. |
| `semi` | Cascade non-intrusive modules; **pause + request approval** before any `intrusive` one. |
| `full` | Cascade everything runnable. Scope is still enforced inside each tool module. |

Dry-run (`--dry-run`) plans and logs what *would* run and **never mutates the State Tree** —
so you can preview a whole engagement on a machine with none of the tools installed.

## Reasoning layer (`atpt/reasoning.py`)
Modules that reason (not just wrap a CLI) call `ctx.reason(prompt, phase)`. It runs
a **provider ladder** from the engagement `config.reasoning`: registered providers
(`cli` / `http_api` / `ollama`), tried in `preference` order, filtered by a per-phase
`policy` (`any` / `hosted_ok` / `local_only`). On a **refusal or error** it advances
to the next provider — ultimately a local model — never rewriting the prompt to defeat
a model's guardrails. Exhaustion returns `None`, so a module falls back to deterministic
logic. API keys are read from env vars (`key_env`) at call time; never stored.

The `map_ptt` module is the first consumer: it maps assets to prioritized **candidate
findings** with deterministic rules, then optionally enriches via `ctx.reason`.

## Adding a module (the extraction pattern)
1. `mkdir modules/<id>` with a `module.json` (id, phase, consumes/provides, intrusive, extracted_from).
2. Add `module.py` with a `Module` subclass implementing `run(ctx) -> ModuleResult`.
3. It's auto-registered. Verify: `atpt modules`.

`extracted_from` records the source repo@commit — provenance for later updates.

## CLI
```bash
atpt init --scope recon/scope.example.json --mode step
atpt modules
atpt plan   --engagement <id> --mode full
atpt run    --engagement <id> --mode semi        # add --dry-run to preview
atpt status --engagement <id> [--json]           # --json for N8N ingestion
atpt approve <module> --engagement <id>          # release a gated intrusive step
```

## How N8N drives this later (topology still open)
- **Execute Command** → `atpt run --engagement X --mode semi --json`
- **Function/IF** → parse `gated_on`; on a gate, a **Wait** node holds for human approval,
  then `atpt approve <module>`.
- **Poll/webhook** → `atpt status --json` feeds dashboards / the final report node.
The core does not depend on N8N; N8N is just one driver.
