# ATPTmaster

Modular autonomous pentest framework for Kali. Start with the **core**: [docs/CORE.md](docs/CORE.md). Vendored integration tools: [tools/MANIFEST.md](tools/MANIFEST.md).

The section below documents the standalone N8N recon node (one driver of the core).

---

# ATPTmaster — Phase 1: Nebula-style Recon Node

N8N orchestrates a thin CLI-wrapper (`recon_runner.sh`) that chains standard
recon tools, normalizes their output into one canonical schema, and writes it to
the **State Tree** (Postgres). This is the data source every later phase consumes.

```
Manual Trigger → Engagement Config → Recon Runner (Execute Command)
              → Normalize (Code) → Persist Assets (Postgres) → Done
```

## Files
| Path | Role |
|---|---|
| `db/schema.sql` | State Tree — `engagements`, `assets`, `findings` (the contract) |
| `recon/scope.example.json` | Scope allow/deny list — enforced at the tool layer |
| `recon/recon_runner.sh` | Nebula-style wrapper: subfinder → naabu → nmap → httpx → ffuf |
| `recon/nmap2json.py` | nmap XML → JSONL bridge |
| `n8n/nodes/normalize.js` | Canonical mapping (source for the Normalize node) |
| `n8n/workflows/p1_recon.json` | Importable N8N workflow |

## Prerequisites (Kali)
```bash
sudo apt install -y jq python3 nmap seclists
# ProjectDiscovery stack:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
```
Confirm `httpx -version` reports **projectdiscovery** (not the Python httpx).

## Deploy
```bash
sudo mkdir -p /opt/atpt/recon
sudo cp recon/recon_runner.sh recon/nmap2json.py /opt/atpt/recon/
sudo cp recon/scope.example.json /opt/atpt/recon/scope.json   # then edit for the real engagement
sudo chmod +x /opt/atpt/recon/recon_runner.sh
```
> Runs assume **N8N native on Kali** so Execute Command sees host tools. If N8N is
> in Docker: bind-mount `/opt/atpt`, install the tools in the N8N image, and run
> the container with host or a scoped bridge network.

## Database
```bash
createdb atpt 2>/dev/null; psql atpt -f db/schema.sql
psql atpt -c "INSERT INTO engagements(id,name) VALUES ('ACME-2026-Q3','ACME Q3') ON CONFLICT DO NOTHING;"
```

## Import & wire the workflow
1. N8N → **Import from File** → `n8n/workflows/p1_recon.json`.
2. Create a **Postgres credential** (`atpt` DB) and bind it on the **Persist Assets** node (imported placeholder id `REPLACE_ME`).
3. Edit **Engagement Config** to your `engagement_id` / `targets` / `tools`.

### The one version-sensitive node: Persist Assets
The node ships as `executeQuery` with 16 positional params via `options.queryReplacement`.
If your Postgres-node version names that field differently, paste this ordered array
into its **Query Parameters** box:
```
{{ [$json.engagement_id, $json.asset_type, $json.value, $json.host, $json.ip, $json.port,
    $json.protocol, $json.service, $json.product, $json.version, $json.http_status,
    $json.http_title, $json.tech, $json.url, $json.source_tool, $json.raw] }}
```
Or switch it to **operation: Insert**, table `assets`, *Map Automatically* — the
normalized item keys already match the columns (you lose upsert, dedup handles repeats).

## Run & verify
Execute the workflow, then:
```bash
psql atpt -c "SELECT asset_type, count(*) FROM assets
              WHERE engagement_id='ACME-2026-Q3' GROUP BY 1 ORDER BY 2 DESC;"
```

## The canonical contract (`assets`)
`asset_type ∈ {subdomain, service, web_endpoint, web_path}`; `value` is the unique
identity; `raw` keeps the full native tool record; `tech` is JSONB. Every downstream
phase reads assets and writes `findings` — same shape, so the Router and Validator
stay tool-agnostic.

## Safety model
Scope is enforced **inside `recon_runner.sh`**, not just in N8N: every seed target,
every discovered subdomain, and every URL is checked against `scope.json`
(`out_of_scope` wins) before any tool touches it. Out-of-scope input is skipped and
logged to stderr. This holds even if the workflow is triggered directly.

## Upgrade path (later)
- Explode the single runner into **one Execute Command node per tool** for per-tool
  retries/visibility (the script is already modular via `--tools`).
- Add an N8N **IF scope-gate** using `recon_runner.sh --check-scope <value>`.
- Swap Manual Trigger → **Webhook/Form/Cron**; add a **Wait** approval gate before ffuf.
- Feed `assets` into **Phase 2 (PentestGPT PTT Router)** to fan out per domain.
