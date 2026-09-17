<p align="center">
  <img src="atpt/assets/logo.png" alt="ATPTmaster" width="320">
</p>

<p align="center"><em>Autonomous Pentest Framework — by Avi Twil</em></p>

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

Modules self-sequence on tokens (`target → asset → finding → validated_finding`). Shipped modules (scope coverage: Web · SQLi · Infra · API · Mobile · LLM · Cloud · Wireless):

| module | phase | intrusive | role | wraps |
|---|---|---|---|---|
| `recon_nebula` | recon | no | subfinder→naabu→nmap→httpx→ffuf, scope-enforced | berylliumsec/nebula |
| `recon_cloud` | recon | no | cloud posture audit (read-only) | prowler |
| `recon_wireless` | recon | no | flag open/WEP APs from an airodump CSV | aircrack-ng |
| `recon_mobile` | recon | no | APK static analysis — exported components | apktool |
| `map_ptt` | map | no | decompose assets → prioritized candidate findings (PTT) | GreyDGL/PentestGPT |
| `map_llm` | map | no | flag LLM/chat prompt-injection surfaces (OWASP LLM01) | native |
| `scan_nuclei` | map | **yes** | active Web/API/Infra vuln scan | nuclei |
| `exploit_hbgpt` | exploit | **yes** | LLM proposes next validation step — **propose-only by default** | hackingBuddyGPT |
| `exploit_sqli` | exploit | **yes** | active SQL-injection testing | sqlmap |
| `validate_xalgorix` | validate | no | verification-first: promote high-confidence, drop false-positives | xalgorix |
| `report_ptes` | report | no | PTES Markdown report | native |

> **Safety model for intrusive modules** (`scan_nuclei`, `exploit_*`): every one enforces
> engagement scope (`atpt/scope.py`) before touching a host, is **gated behind human approval
> in `semi` mode**, and **no-ops cleanly when its tool is absent** (so the framework installs
> anywhere). `exploit_hbgpt` is **propose-only** by default — it logs the LLM's suggested next
> step; actual execution is opt-in (`config.exploit.execute`) and additionally restricted to a
> read-only command allowlist. No module rewrites prompts to bypass a model's guardrails.
> Run intrusive modules only against systems you are **authorized** to test.

## Install

Zero-dependency core — Python ≥ 3.10 stdlib only. The optional scanners are never
installed silently; add them with `--with-tools`.

**One-line install:**

```bash
git clone https://github.com/avitwil/ATPTmaster.git atpt && cd atpt && ./install.sh
```

More options:

```bash
./install.sh                 # core setup + report which optional tools are present
./install.sh --pipx          # also expose the `atpt` command (via pipx)
./install.sh --with-tools    # also install the optional scanners (sudo apt + go install)
```

Optional tools by module (each module no-ops cleanly if its tool is missing):
`nmap sqlmap jq aircrack-ng apktool` (apt) · `subfinder naabu httpx nuclei ffuf`
(`go install`) · `prowler` (cloud, `pipx`) · `ollama` (local LLM, optional).

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

### ⚙ Settings

A **Settings** dropdown (header) configures, without editing JSON:

- **Providers (API key)** — hosted providers; per provider, *paste* a key (stored
  on this machine) **or** name an *env var* (read at call time, nothing stored).
  Stored keys are **redacted** everywhere they're read back.
- **Subscription CLI** — CLIs you're logged into. **Claude, Gemini and Codex are
  offered by default** (or add a **custom** one with its own name + full command).
  One **Install (auto)** click installs any missing dependency (Node.js + npm) and
  the CLI itself under `sudo` — the only thing you're asked for is your **sudo
  password** (memory-only). The reasoning command is the resolved binary path
  (e.g. `/usr/bin/claude -p`), so runs don't depend on `PATH`.
- **Local LLM** — Ollama models. **Model ladder** — order the fallback preference and
  set a per-phase policy (`any` / `hosted_ok` / `local_only`).
- **Operator** — pentester name (appears on the report), light/dark theme, and
  **Allow sudo** (privileged scans). The sudo password is **held in memory only** —
  never written to disk, never logged, re-asked after a restart.
- **CTF** (per engagement) — VPN config path, **goals** (injected into the LLM's
  prompts so it knows the objective), and attack-box host/user. The attack-box SSH
  password, like the sudo password, is **kept in memory only**.

Provider/ladder/name/sudo settings are global; CTF settings attach to the selected
engagement. Reasoning config set here is used by runs (engagement config overrides
the global default).

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

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE). © 2026 Avi Twil.

Bundled third-party tools under `tools/` retain their own upstream licenses.
