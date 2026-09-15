# Vendored Integration Tools — Provenance

Cloned shallow (`--depth 1`) for study/extraction. Pinned to the commit we
integrate against. Re-fetch full history with `git -C tools/<name> fetch --unshallow`.
All licenses permissive (BSD/Apache/MIT) — extraction/adaptation allowed with attribution.

| Tool | Repo | Commit (pinned) | License | Stack | Size | Role in ATPT |
|---|---|---|---|---|---|---|
| nebula | berylliumsec/nebula | `e795eaa` | BSD-2-Clause | Python + TS/Docker | 95M | Phase 1 — CLI-wrapper recon logic |
| xalgorix | xalgorix/xalgorix | `fa7ca43` | Apache-2.0 | Go + TS/Docker | 35M | Phase 4 — verification-first PoC validation (22-phase) |
| pentestgpt | GreyDGL/PentestGPT | `e8b1bb7` | MIT | Python/Docker | 2.3M | Cross-cutting — State Tree (PTT) + task decomposition |
| strix | usestrix/strix | `84f4108` | Apache-2.0 | Python/Docker | 15M | Phase 3 — multi-agent web/app exploitation |
| pentagi | vxcontrol/pentagi | `ea66530` | MIT (+EULA, lawful-use) | Go + TS/Docker/Compose | 151M | Phase 3 — autonomous multi-agent, Neo4j knowledge graph |
| hackingbuddygpt | ipa-lab/hackingBuddyGPT | `799f57e` | MIT | Python | 4.6M | Phase 3 — flexible framework for custom SSH/shell agents |

## Notes
- **PentAGI**: source is MIT; the bundled `EULA.md` layers "lawful penetration-testing only"
  terms but states MIT prevails for the source. Backend = Go, frontend = TS, heavy Compose
  stack (observability, Graphiti/Neo4j). Treat as a service to call, not a lib to import.
- **Xalgorix**: Go core + TS webui; its `internal/` holds the verifier logic we want for Phase 4.
- **Nebula**: Python core in `src/`; recon/CLI-wrapping + provenance artifacts are the target.
- **PentestGPT**: smallest + most surgical to extract from — `pentestgpt_agent/` + `unified_agent/`
  hold the reasoning/PTT logic; `pentestgpt_legacy/` is the interactive multi-provider mode.
- **hackingBuddyGPT**: `src/` use-case pattern ("agent in ~50 LOC") is the template for our custom agents.
- **Strix**: `strix/` package + `skills/` + `containers/` — agent loop and sandboxed tool runners.

_Nothing here has been installed or executed. No pip/npm/go build/docker run performed._
