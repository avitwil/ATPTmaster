# N8N integration

ATPTmaster is **orchestrator-agnostic**: the engine runs via the `atpt` CLI and
N8N drives it by shelling out. Nothing here is required to use the tool — the CLI
and web console (`atpt serve`) work standalone.

## Workflows

- **`workflows/atpt_pipeline.json`** — full-pipeline driver. `Config → atpt init →
  atpt run (--json) → Summarize + Next Step → atpt status → Done`. The Summarize
  node parses `gated_on`: when an intrusive step is waiting, it prints the exact
  `atpt approve …` command to run before continuing.
- **`workflows/p1_recon.json`** — standalone recon workflow (recon_runner.sh →
  normalize → Postgres). Predates the CLI driver; kept as a native-node example.
- **`nodes/normalize.js`** — the recon JSONL→assets normalizer used by p1_recon.

Import a workflow in N8N: *Workflows → Import from File*. Edit the **Config** node
(`home`, `engagement`, `scope_file`, `mode`).

## The command surface N8N drives

```bash
ATPT_HOME=/opt/atpt python3 -m atpt init  --scope <scope.json> --engagement <id> --mode semi
ATPT_HOME=/opt/atpt python3 -m atpt run   --engagement <id> --mode semi --json   # {executed, gated_on}
ATPT_HOME=/opt/atpt python3 -m atpt approve <module> --engagement <id>            # release a gate
ATPT_HOME=/opt/atpt python3 -m atpt status --engagement <id> --json
# report is written to $ATPT_HOME/var/reports/<id>.md when the report phase runs
```

## Approval gate (semi mode) — the Wait pattern

In `semi` mode `atpt run --json` stops before each **intrusive** module and returns
`{"gated_on": "<module>", ...}`. To automate the human-in-the-loop:

1. **IF** node on `{{ $json.gated_on }}` (is not empty).
2. **true →** a **Wait** node (`Resume: On Webhook Call`) — pauses until an operator
   POSTs the resume URL (your approval UI/Slack button). Then an **Execute Command**
   running `atpt approve {{gated_on}} --engagement <id>`, and loop back to `atpt run`.
3. **false →** the queue is drained; run `atpt status --json` and read the report.

`full` mode runs intrusive modules without gating (scope is still enforced inside
each module) — use it only for authorized, unattended engagements.

## Connecting an LLM

Reasoning providers are read from the engagement `config.reasoning` (see the root
README). API keys come from environment variables in N8N's execution environment
(e.g. `ANTHROPIC_API_KEY`) — never put keys in the workflow JSON.

## Modules the pipeline will walk (by phase)

`recon` recon_nebula · recon_cloud · recon_wireless · recon_mobile →
`map` map_ptt · map_llm · scan_nuclei →
`exploit` exploit_hbgpt · exploit_sqli →
`validate` validate_xalgorix →
`report` report_ptes. Intrusive modules (`scan_nuclei`, `exploit_*`) gate in `semi`.
