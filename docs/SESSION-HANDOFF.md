# ATPTmaster — Session Handoff Prompt

Paste the block below into a new Claude Code session started in
`/home/avi/Projects/claude_projects/ATPTmaster`.

---

Act as a **Senior Offensive Security Architect and AI Agent Integration Expert**.

I'm building **ATPTmaster** — a modular, autonomous penetration-testing framework on
**Kali Linux**, orchestrated by **N8N**. Philosophy: **integration-first** — do NOT
reinvent; **extract and adapt** the best features from existing open-source AI security
tools into one unified system. Working dir: `/home/avi/Projects/claude_projects/ATPTmaster`.

**Locked requirements**
- Modular: drop-in capability modules, independently updatable.
- Installable on any Kali box: zero-dependency (stdlib-only) core.
- Three run modes: step-by-step / semi-auto / full-auto.
- Extraction posture: take only what we need from each tool.
- Eventual scope: Web, SQLi, Infra, API, Mobile (Frida/APK), LLM prompt injection, Cloud, Wireless.
- Reporting: final LLM node → PTES Markdown (CVSS, OWASP mapping, remediation, raw evidence).

**Boundary set:** do not build prompt tooling whose purpose is bypassing another model's
safety guardrails. For uncensored exploitation reasoning, plan to use a self-hosted local
model (Ollama on Kali); reserve hosted models for parsing/orchestration/reporting.

**ALREADY BUILT — read these first, then confirm you're synced:**
- `docs/CORE.md` — core architecture.
- `tools/MANIFEST.md` — 6 vendored integration tools, pinned commits.
- `atpt/` — stdlib-only core: `module.py` (contract), `registry.py`, `state.py`
  (SQLite State Tree), `engine.py` (phase-walk + run modes + approval gating), `cli.py`.
- `modules/recon_nebula/` — first extracted module (recon); proves the contract.
- `tests/test_core.py` — 4 passing tests (`python3 -m unittest tests.test_core`).
- `recon/recon_runner.sh` — Nebula-style CLI wrapper (subfinder→naabu→nmap→httpx→ffuf);
  enforces scope at the tool layer. `recon/nmap2json.py`, `recon/scope.example.json`.
- `db/schema.sql` — Postgres schema (canonical contract; mirrors the SQLite store).
- `n8n/workflows/p1_recon.json` + `n8n/nodes/normalize.js` — standalone N8N recon workflow (one future driver).

The core runs standalone via the `atpt` CLI (`init | modules | plan | run | status | approve`)
and is **orchestrator-agnostic**. N8N will drive it later by shelling out to `atpt`.
**Topology (N8N native vs Docker) is deliberately deferred.**

**Vendored tools & roles** (`tools/<name>`, pinned; all permissive licenses):
| name | commit | license | role | status |
|---|---|---|---|---|
| nebula | e795eaa | BSD-2 | recon CLI-wrapping | DONE → recon_nebula |
| pentestgpt | e8b1bb7 | MIT | State Tree (PTT) + task decomposition → `map` phase | pending |
| xalgorix | fa7ca43 | Apache-2 | verification-first PoC validation → `validate` phase | pending |
| strix | 84f4108 | Apache-2 | multi-agent web/app exploitation → `exploit` | pending |
| pentagi | ea66530 | MIT | autonomous multi-agent platform (run as service) → `exploit` | pending |
| hackingbuddygpt | 799f57e | MIT | ~50-LOC agent template for custom SSH/shell → `exploit` | pending |

**Module contract (how to add one):**
1. `mkdir modules/<id>` + `module.json`: `id, name, phase, entrypoint "module:Class",
   consumes[], provides[], intrusive, run_modes[], extracted_from "repo@commit"`.
2. `module.py`: subclass `atpt.module.Module`, implement `run(ctx) -> ModuleResult`
   (assets/findings/summary); honor `ctx.dry_run` (plan only, no state mutation).
3. Phases: `scope→recon→map→exploit→validate→post→report`.
   Tokens: `target, asset, finding, validated_finding`. Auto-registered; verify `atpt modules`.

**WHERE WE LEFT OFF — choose the next module to extract:**
1. **Map/PTT router** from PentestGPT (phase `map`, consumes `asset`) — the brain that
   routes recon→exploit. Recommended next (next in phase order, unlocks downstream).
2. **Validator** from Xalgorix (phase `validate`, consumes `finding`).
3. **First exploit agent** from hackingBuddyGPT (phase `exploit`, `intrusive=true` — exercises the approval gate for real).
4. **Wire N8N as a driver** (Execute Command → `atpt run --json`; Wait-for-approval; status polling).

Read `docs/CORE.md`, `tools/MANIFEST.md`, and `atpt/engine.py` first, confirm you're synced,
then continue with option **[I will pick]**. Do NOT reinvent the core — extend it through the module contract.

---
