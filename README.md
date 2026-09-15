# ATPTmaster

A modular, autonomous **penetration-testing framework** for Kali Linux. Integration-first:
it extracts and adapts the best of existing open-source AI-security tools into one unified,
orchestrator-agnostic engine with a web console.

- **Zero-dependency core** — pure Python stdlib. No pip install. Runs on any Kali box.
- **Modular** — drop-in capability modules, auto-registered from `modules/<id>/`.
- **Three run modes** — `step` (one module at a time), `semi` (auto until an intrusive step, then pause for approval), `full` (auto).
- **Bring your own LLM** — connect one or more models (hosted API key, an existing CLI login, or a local Ollama). Each operator uses their own keys; nothing proprietary is bundled.
- **Reporting** — a final node renders a **PTES-compliant Markdown** report (CVSS, OWASP, remediation, raw evidence) you can download.

## Pipeline

```
scope → recon → map → exploit → validate → report
```

Modules self-sequence on tokens (`target → asset → finding → validated_finding`). Shipped modules:

| module | phase | role | extracted from |
|---|---|---|---|
| `recon_nebula` | recon | subfinder→naabu→nmap→httpx→ffuf wrapper, scope-enforced | berylliumsec/nebula |
| `map_ptt` | map | decompose assets → prioritized candidate findings (PTT) | GreyDGL/PentestGPT |
| `validate_xalgorix` | validate | verification-first: promote high-confidence, drop false-positives | xalgorix/xalgorix |
| `report_ptes` | report | PTES Markdown report | native |

> Intrusive live exploitation (SSH/shell agents) is intentionally **not** enabled in this
> shareable build — the approval gate exists, but autonomous exploitation ships as a separate,
> explicitly-enabled module.

## Quick start

```bash
# 1. launch the console (stdlib http.server, binds to 127.0.0.1)
python3 -m atpt serve            # → http://127.0.0.1:8787

# 2. in the browser: click "Load demo" (no tools needed) → Run full → Download report
```

Or drive it from the CLI:

```bash
python3 -m atpt init --scope recon/scope.example.json --mode semi
python3 -m atpt run --engagement <id> --mode semi
python3 -m atpt status --engagement <id>
python3 -m atpt approve <module> --engagement <id>   # release a gated intrusive step
```

Run the tests (stdlib `unittest`, nothing installed or executed externally):

```bash
python3 -m unittest discover -s tests
```

## Web console

`atpt serve` opens a single-page console:

1. **Define scope & target** (required before any run) — or **Load demo**.
2. **Chat control** — `run` / `plan` / `status` / `approve <module>` / `report`, plus buttons.
3. **Findings** table and an **attack-direction tree** (the PTT, grouped by domain, ranked by severity).
4. **Download report** — the PTES Markdown deliverable.

## Connecting an LLM (optional, for adaptive reasoning)

Reasoning modules call a **provider ladder** — try providers in your preference order, fall
back to the next on refusal/error (ending at a local model), never rewriting a prompt to defeat
a model's guardrails. Configure per engagement:

```json
"reasoning": {
  "providers": {
    "my_claude": { "backend": "http_api", "api": "anthropic", "model": "claude-opus-5", "key_env": "ANTHROPIC_API_KEY" },
    "my_openai": { "backend": "http_api", "api": "openai",    "model": "gpt-5",         "key_env": "OPENAI_API_KEY" },
    "claude_cli":{ "backend": "cli",      "cmd": "claude -p" },
    "local":     { "backend": "ollama",   "model": "llama3.1" }
  },
  "preference": ["my_claude", "my_openai", "local"],
  "policy": { "map": "any", "report": "hosted_ok" }
}
```

API keys are read from **environment variables** at call time — never stored, logged, or placed in a URL.

## Security notes

- The console binds to `127.0.0.1` by default — it is an operator tool, not a public service. Exposing it (`--host 0.0.0.0`) has no authentication; don't.
- Only test systems you are **authorized** to test. Scope is enforced at the recon tool layer and required before any run.

## Architecture

See [`docs/CORE.md`](docs/CORE.md) for the engine, the module contract, and the reasoning layer.
Design specs and implementation plans live under [`docs/superpowers/`](docs/superpowers/).
