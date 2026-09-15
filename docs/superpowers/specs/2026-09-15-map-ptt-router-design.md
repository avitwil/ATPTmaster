# Design — `map_ptt` router + `atpt` reasoning ladder

- **Date:** 2026-09-15
- **Status:** approved for spec review
- **Phase:** `map` (fills the recon→exploit gap)
- **Extracted from:** `GreyDGL/PentestGPT@e8b1bb7` (PTT / task decomposition;
  provider-agnostic backend idea from its `unified_agent`)

## 1. Context & goal

The engine's token pipeline is `scope→recon→map→exploit→validate→post→report`,
gated on `target/asset/finding/validated_finding`. Today recon produces the
`asset` token, but **nothing consumes `asset` to produce `finding`**, so the
engine drains after recon and no exploit/validate module can ever become
runnable. This design adds the keystone `map` module and, because it is the
first module that *reasons* rather than wraps a CLI, the framework-wide
reasoning layer it needs.

Two deliverables:

1. **`modules/map_ptt/`** — decomposes the asset inventory into prioritized
   **candidate findings** (attack hypotheses), the PTT concept adapted to our
   flat `findings` table. Non-intrusive.
2. **`atpt/reasoning.py`** — a stdlib-only **provider ladder**: user-registered
   providers, an ordered preference list, and automatic fallback to the next
   provider on refusal/error, terminating in deterministic rules. Exposed to any
   module via `ctx.reason(...)`. `map_ptt` is its first consumer; validate /
   exploit / report reuse it.

## 2. Locked constraints honored

- **Stdlib-only core** — reasoning layer uses only `urllib.request` (HTTP) and
  `subprocess` (CLI). No third-party SDKs.
- **Zero-dependency install** — with no providers configured (and no LLM
  present), `map_ptt` runs rules-only and the pipeline still flows.
- **Hosted vs local split** — enforced by a per-phase `policy` knob, not
  hardcoded. Sensitive reasoning can be pinned `local_only`.
- **No guardrail-bypass tooling** — a refusal advances the ladder to the next
  provider (ending at a local model the operator runs themselves). We never
  build prompt tricks whose purpose is to circumvent a model's safety
  guardrails. This is a hard boundary.

## 3. Scope

**In:** `map_ptt` module (manifest + rules + orchestration); `atpt/reasoning.py`
ladder with `cli` / `http_api` / `ollama` backends and rules fallback;
`RunContext.reason` wiring; one core read method `list_assets`; config schema for
`reasoning` and `map`; TDD tests.

**Out (YAGNI / future):** an explicit PTT tree table (priority ordering on flat
findings suffices now); exploit/validate/report modules (they consume this layer
later); streaming/async provider calls; a credential UI (keys come from env vars
/ existing CLI logins).

## 4. Architecture

```
recon_nebula ──asset──▶ [ assets table ]
                              │
                     map_ptt.run(ctx)
                              │  read
                     store.list_assets(eid)
                              │
                 ┌────────────┴─────────────┐
                 │  rules.py (deterministic) │  asset ─▶ candidate findings
                 └────────────┬─────────────┘
                              │  optional enrich
                     ctx.reason(prompt, phase="map")
                              │
                 atpt/reasoning.py — provider ladder
                 (cli / http_api / ollama ; refusal→next ; exhausted→None)
                              │
                 merge + dedupe ─▶ ModuleResult(findings=[candidate...])
                              │
                     engine upsert_finding ─▶ [ findings table ] ──finding──▶ exploit/validate
```

## 5. `modules/map_ptt/`

### 5.1 `module.json`
```json
{
  "id": "map_ptt",
  "name": "PTT Attack-Surface Router",
  "phase": "map",
  "entrypoint": "module:MapPTT",
  "consumes": ["asset"],
  "provides": ["finding"],
  "intrusive": false,
  "run_modes": ["step", "semi", "full"],
  "enabled": true,
  "extracted_from": "GreyDGL/PentestGPT@e8b1bb7",
  "description": "Decomposes assets into prioritized candidate findings (PTT); deterministic rules + optional reasoning-ladder enrichment."
}
```

### 5.2 `rules.py` — deterministic mapping (pure, no I/O)
A list of matchers `rule(asset) -> list[candidate]`. Each candidate is a
`finding` dict:
`{title, domain, severity, cvss, owasp, status:"candidate", asset_id, evidence, source_tool:"map_ptt", priority}`.

Seed ruleset (extend later without touching orchestration):

| asset signal | candidate finding | domain | owasp | severity |
|---|---|---|---|---|
| `service=ssh` / port 22 | Credential attack surface (SSH) | Infra | A07 | medium |
| `service in {ftp,telnet}` | Cleartext service exposed | Infra | A02 | medium |
| `service in {mysql,postgres,redis,mongo,...}` | Exposed data service | Infra | A05 | high |
| `asset_type=web_endpoint` + `tech` matches known product | Known-CVE candidate (`<product>`) | Web | A06 | high |
| `web_path` matches `/admin,/login,/.git,/.env,/actuator,...` | Sensitive path exposed | Web | A05/A01 | high |
| `http_status in {401,403}` | Auth-protected surface (bypass candidate) | Web | A01 | medium |
| `asset_type=web_endpoint` (generic) | Web app entry (injection/XSS surface) | Web | A03 | low |

`priority` = deterministic score from severity + signal specificity; used for
ordering (the "tree" as a ranked list). Candidates deduped on
`(asset_id, title)`.

### 5.3 `module.py` — `MapPTT(Module)`
- `run(ctx)`: `assets = ctx.store.list_assets(eid)`; `cands = rules.map_assets(assets)`.
- Optional enrichment: if a reasoning provider is available and policy permits,
  build a compact JSON prompt (asset summary + current candidates) and call
  `text = ctx.reason(prompt, phase="map")`. Parse a strict JSON contract
  (list of candidate objects); invalid/empty → ignore (rules stand). Merge +
  dedupe. Record the winning provider name in each enriched candidate's
  `evidence.provenance`.
- `ctx.dry_run`: compute rule candidates, emit a plan event with counts, **persist
  nothing**, return `ModuleResult(planned=[...], summary=...)`.
- Returns `ModuleResult(findings=cands, summary="N candidate findings from M assets")`.
- Any exception in enrichment is caught → rules-only result (never fails the run).

## 6. `atpt/reasoning.py` — the provider ladder

### 6.1 Interface
```python
class ReasoningLadder:
    def __init__(self, config: dict): ...
    def reason(self, prompt: str, phase: str) -> ReasoningResult | None: ...
        # returns first usable result, else None (caller falls back to rules)

@dataclass
class ReasoningResult:
    text: str
    provider: str          # which registered provider produced it
    status: str            # "ok"
```

### 6.2 Resolution algorithm
1. Take `config.reasoning.preference` (ordered provider names).
2. Filter by `config.reasoning.policy[phase]`:
   `"any"` → all; `"local_only"` → only `ollama` backends; `"hosted_ok"` → all;
   unknown/missing phase → default `"any"`.
3. For each provider in order, dispatch to its backend:
   - **`ok`** (non-empty, not classified as refusal) → return `ReasoningResult`.
   - **`refused`** → `emit` a `reasoning_refused` event, continue to next.
   - **`error`/unavailable** (missing CLI, timeout, missing key, non-2xx, bad
     payload) → `emit` a `reasoning_error` event, continue to next.
4. List exhausted → return `None`.

**Refusal handling is routing, not bypass.** On refusal we move to the next
provider — ultimately a local model the operator runs. We never mutate the
prompt to defeat the refusing model's guardrails.

### 6.3 Backends (each ~15–30 LOC, stdlib only)
| backend | mechanism | auth |
|---|---|---|
| `cli` | `subprocess.run([...cmd, prompt])`, capture stdout | existing CLI login (e.g. `claude -p`, `codex exec`) — no key handling by us |
| `http_api` | `urllib.request` POST; `api` field selects the wire shape — `anthropic` (`/v1/messages`, `x-api-key`, `anthropic-version`, `messages[]`+`max_tokens`) or `openai` (default: `/v1/chat/completions`, `Bearer`, `messages[]`). Explicit `endpoint` overrides the default URL. | API key read from `os.environ[provider["key_env"]]` at call time only |
| `ollama` | `urllib.request` POST `http://localhost:11434/api/generate` (reads `.response`) | none (local) |

### 6.4 Refusal classifier
Small heuristic, deterministic: empty/near-empty output, or output matching a
short refusal-phrase set, or (when a JSON contract is expected) no parseable
result → classified `refused`. Purpose is *advance the ladder*, never to detect
"how to get around" a model.

### 6.5 Secrets & privacy
- API keys are referenced by **env-var name** (`key_env`) and read at call time.
  Never stored in the engagement DB, never placed in a URL/query string, never
  logged. Events log only provider name + status.
- `cli` backend relies on the CLI's own stored auth; ATPT handles no token.

## 7. Config schema (engagement `config` JSON)
```json
{
  "reasoning": {
    "providers": {
      "claude_cli": { "backend": "cli",      "cmd": "claude -p" },
      "anthropic":  { "backend": "http_api", "api": "anthropic", "model": "claude-opus-5", "key_env": "ANTHROPIC_API_KEY" },
      "openai":     { "backend": "http_api", "api": "openai",    "model": "gpt-5",        "key_env": "OPENAI_API_KEY" },
      "local":      { "backend": "ollama",   "model": "llama3.1" }
    },
    "preference": ["claude_cli", "anthropic", "local"],
    "policy": { "map": "any", "exploit_reasoning": "local_only", "report": "hosted_ok" }
  },
  "map": { "enrich": true }
}
```
All keys optional. Absent `reasoning` / empty `preference` → `ctx.reason` returns
`None` → rules-only.

## 8. Core additions (minimal, additive)
- `atpt/state.py`: `list_assets(eid) -> list[dict]` — returns asset rows incl.
  integer `id` (for `finding.asset_id` linkage). First asset *read* API; only
  counts exist today.
- `atpt/reasoning.py`: new module (section 6).
- `atpt/module.py` `RunContext`: add `reason(self, prompt, phase) -> str | None`
  thin handle. Wired by `cli.py`/engine to a `ReasoningLadder` built from the
  engagement config; returns `result.text` or `None`. No change to the `Module`
  contract or `Manifest`.

## 9. Finding shape produced
```json
{
  "asset_id": 12, "title": "Exposed data service (redis)",
  "domain": "Infra", "severity": "high", "cvss": 7.5, "owasp": "A05",
  "status": "candidate", "source_tool": "map_ptt",
  "evidence": { "asset_value": "10.0.0.5:6379/redis", "rule": "exposed_data_service",
                "priority": 82, "provenance": "rules" }
}
```
`upsert_finding` already accepts exactly these fields; no schema change.

## 10. Pipeline effect
After `map_ptt` runs, `count_findings(eid) > 0` → `_satisfied` adds the `finding`
token → any module consuming `finding` (exploit/validate) becomes runnable. The
keystone is in place.

## 11. Testing (TDD — write tests first)
`tests/test_map_ptt.py` and `tests/test_reasoning.py`:
- **rules**: ssh asset → credential candidate with expected `domain`/`owasp`/`severity`; web_path `/admin` → sensitive-path candidate; dedupe on `(asset_id,title)`.
- **module.run**: given seeded assets in an in-memory store, persists candidate findings and flips the `finding` token (assert via `_satisfied` / a pending exploit stub becomes runnable).
- **dry_run**: `count_findings` unchanged; `planned` populated.
- **enrich graceful degradation**: provider that errors/refuses → rules-only result, no exception.
- **ladder order**: preference respected; `refused` advances to next; `error` advances; exhausted → `None`.
- **policy**: `local_only` filters out non-`ollama` providers for that phase.
- **secrets**: `http_api` reads key from env var; missing env var → `error`+advance (never crash, never log the key).
- **registry**: `atpt modules` lists `map_ptt`.
- Existing `tests/test_core.py` (4) stay green.

All network/CLI calls in tests are stubbed (monkeypatched) — **no real provider
or tool is contacted**, consistent with "nothing vendored is executed."

## 12. File manifest
```
modules/map_ptt/module.json      new
modules/map_ptt/rules.py         new (pure ruleset)
modules/map_ptt/module.py        new (MapPTT orchestration)
atpt/reasoning.py                new (provider ladder + backends)
atpt/state.py                    +list_assets
atpt/module.py                   RunContext.reason handle
atpt/cli.py / engine.py          wire ReasoningLadder from engagement config
tests/test_map_ptt.py            new
tests/test_reasoning.py          new
docs/CORE.md                     note the reasoning layer + map phase
```

## 13. Boundary statement (restated)
ATPT will **not** include tooling whose purpose is bypassing another model's
safety guardrails. The ladder's response to a refusal is to route to the next
configured provider — including a local uncensored model the operator runs
themselves for authorized engagements — never to defeat the refusing model.
