# Settings UI + Provider/CTF configuration — Design Spec

**Date:** 2026-09-17
**Branch:** `feat/settings-ui`
**Status:** Approved, implementing

## Goal

Add a **Settings dropdown** to the web console so an operator can configure LLM
providers, a model ladder, operator identity, theme, sudo elevation, and
per-engagement CTF parameters — closing the gap where the documented `reasoning`
config had no way to be set through the UI or CLI.

## Decisions (locked)

- **API keys:** per-provider choice — *paste* (stored in DB) **or** *env-var name*
  (read from environment at call time).
- **Sudo password:** **session-memory only** — held in the server process, never
  written to disk, never logged, never returned by any GET. Re-asked on restart.
  Fallback to `sudo -n` (NOPASSWD) when no password is set.
- **Scope:** providers/ladder/name/sudo are **global** (`app_settings`); VPN/goals/
  attack-box are **per-engagement** (engagement `config.ctf`). Theme is client-side.
- **Wiring this round:** name→report, goals→LLM prompt, providers→engine fallback,
  sudo→toolwrap. VPN/attack-box are **stored + validated only** (connect/SSH deferred).
- **Subscription CLIs:** curated install registry for `claude`, `gemini`, `codex`.
  Not installed → show install cmd + Install button (permission-gated) → Log in
  streams output and surfaces device-code URL/code, with a "run in terminal" fallback.

## Components

### state.py
- `app_settings` table: single row `(id=1, data TEXT json)`.
- `get_settings() -> dict`, `set_settings(dict)` (merge).
- `update_engagement_config(eid, patch: dict)` — deep-merge patch into config JSON.

### privilege.py (new)
- Process-global sudo state: `set_allowed(bool)`, `is_allowed()`,
  `set_password(pw)`, `clear_password()`.
- `sudo_invocation() -> (prefix_argv | None, stdin | None)`:
  not allowed → `(None, None)`; allowed+pw → `(["sudo","-S","-p",""], pw+"\n")`;
  allowed+no pw → `(["sudo","-n"], None)`.
- Passwords live only here, in memory.

### toolwrap.py
- `run(argv, timeout=300, sudo=False)`: when `sudo=True`, consult
  `privilege.sudo_invocation()`; `-3` return if sudo not enabled; feed password via
  stdin. Non-sudo path unchanged.

### engine.py
- `_ctx`: reasoning config = engagement `config.reasoning` **or** global
  `settings.reasoning`. Read `config.ctf.goals` and pass to `RunContext(goals=...)`.

### module.py
- `RunContext.goals: str = ""`. `reason()` prepends
  `"Engagement goals: <goals>\n\n"` to the prompt when goals are set.

### modules/report_ptes/module.py
- `build_report_md` adds `- **Prepared by:** <pentester_name>` when set.

### providers.py (new)
- `REGISTRY = {claude, gemini, codex}` → `{binary, install: [argv], login: [argv], help}`.
- `status(binary) -> {installed: bool, path}` via `shutil.which`.
- `install(name)` / `login(name)` run subprocesses (called from web layer).

### web.py
- Routes: `GET/POST /api/settings`, `POST /api/settings/sudo-password` (no GET),
  `GET/POST /api/settings/ctf?eng=`, `GET /api/providers/status`,
  `POST /api/providers/install`, `POST /api/providers/login`.
- **Redaction:** GET `/api/settings` never returns stored API-key values — only
  `has_key: true`. POST with empty key keeps the existing value.
- INDEX_HTML: ⚙ Settings button in header → modal with the panels; light/dark via
  `data-theme` + `localStorage`; light palette added to CSS `:root[data-theme=light]`.

## Testing (stdlib unittest)
- settings round-trip; API-key redaction on GET; empty-key preserves stored value.
- engine uses global reasoning when engagement has none; engagement overrides global.
- goals injected into reason() prompt.
- toolwrap sudo builds `sudo -S`/`sudo -n`; password never touches disk (grep DB).
- report shows pentester name.
- providers registry lookup + which-detection; unknown provider handled.
- CTF config deep-merge; sudo-password endpoint stores nothing in DB and has no GET.

## Deferred (not v1)
Live openvpn connect/disconnect; real attack-box SSH command execution.
