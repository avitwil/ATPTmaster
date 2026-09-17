"""Stdlib web UI for ATPTmaster — chat-driven control + findings + attack tree +
PTES report download. No third-party deps: http.server + a single embedded page.

Routing lives in `WebApp.handle(method, path, query, body) -> (status, ctype, bytes, headers)`
so it is unit-testable without opening a socket. `serve()` wraps it in a threading
HTTP server; each request opens its own SQLite connection (thread-safe by construction).
Binds to 127.0.0.1 by default — this is an operator console, not a public endpoint.
"""
from __future__ import annotations
import copy
import importlib.util
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import privilege, providers
from .engine import Orchestrator
from .registry import discover
from .state import SQLiteStore

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Engagement ids become filesystem path segments (var/reports/<id>.md) and scope
# filenames, so they are strictly whitelisted — no slashes, no dot-only ids.
_VALID_EID = re.compile(r"[A-Za-z0-9_-]{1,64}$")


def valid_eid(eid: str) -> bool:
    return bool(eid) and eid not in (".", "..") and _VALID_EID.match(eid) is not None


def _h(s) -> str:
    """Escape user-derived text placed into an HTML (innerHTML) reply string."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _load_report_builder(project_dir: Path):
    p = Path(project_dir) / "modules" / "report_ptes" / "module.py"
    spec = importlib.util.spec_from_file_location("report_ptes_web", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_report_md


def _redact_settings(s: dict) -> dict:
    """Return a copy safe to send to the client: stored API keys become a
    boolean `has_key` presence flag — the value never leaves the server."""
    s = copy.deepcopy(s or {})
    for p in (s.get("reasoning", {}) or {}).get("providers", {}).values():
        if isinstance(p, dict) and p.get("api_key"):
            p.pop("api_key", None)
            p["has_key"] = True
    return s


def _preserve_reasoning_keys(incoming: dict, existing: dict) -> dict:
    """When a provider is posted without an api_key (blank/omitted), keep the
    previously stored key rather than wiping it. Also strips any `has_key` marker
    a client echoed back so it never lands in storage."""
    inc = (incoming.get("reasoning") or {}).get("providers")
    if not isinstance(inc, dict):
        return incoming
    ex = (existing.get("reasoning") or {}).get("providers", {})
    for name, p in inc.items():
        if not isinstance(p, dict):
            continue
        p.pop("has_key", None)
        if not p.get("api_key"):
            p.pop("api_key", None)
            old = ex.get(name) if isinstance(ex, dict) else None
            if isinstance(old, dict) and old.get("api_key"):
                p["api_key"] = old["api_key"]
    return incoming


def _parse_evidence(f: dict) -> dict:
    ev = f.get("evidence")
    if isinstance(ev, str):
        try:
            return json.loads(ev)
        except Exception:
            return {"raw": ev}
    return ev if isinstance(ev, dict) else {}


class WebApp:
    def __init__(self, project_dir, db_path=None):
        self.project_dir = Path(project_dir)
        self.db_path = Path(db_path) if db_path else self.project_dir / "var" / "atpt.db"

    def _store(self) -> SQLiteStore:
        return SQLiteStore(self.db_path)

    def _orch(self, store) -> Orchestrator:
        return Orchestrator(store, discover(self.project_dir / "modules", self.project_dir),
                            self.project_dir)

    # ---- helpers ------------------------------------------------------------
    @staticmethod
    def _json(status, obj, headers=None):
        return status, "application/json; charset=utf-8", json.dumps(obj).encode(), headers or {}

    def _status_obj(self, store, eid) -> dict:
        return {
            "engagement": eid, "assets": store.count_assets(eid),
            "asset_types": store.asset_type_counts(eid),
            "findings": store.count_findings(eid),
            "candidates": store.count_findings(eid, status="candidate"),
            "validated": store.count_findings(eid, status="validated"),
            "false_positives": store.count_findings(eid, status="false_positive"),
            "pending_approvals": store.pending_approvals(eid),
            "events": store.recent_events(eid, 60)[::-1],
        }

    def _tree(self, store, eid) -> dict:
        eng = store.get_engagement(eid) or {"name": eid}
        branches: dict[str, list] = {}
        for f in store.list_findings(eid):
            if f.get("status") == "false_positive":
                continue
            dom = f.get("domain") or "General"
            branches.setdefault(dom, []).append({
                "title": f.get("title"), "severity": (f.get("severity") or "info"),
                "status": f.get("status"), "cvss": f.get("cvss"), "owasp": f.get("owasp")})
        for lst in branches.values():
            lst.sort(key=lambda x: _SEV_ORDER.get((x["severity"] or "info").lower(), 9))
        return {"target": eng.get("name") or eid,
                "branches": [{"domain": d, "findings": branches[d]} for d in sorted(branches)]}

    # ---- routing ------------------------------------------------------------
    def handle(self, method, path, query, body):
        try:
            return self._route(method, path, query, body)
        except Exception:  # never 500-crash the console; don't leak internals
            import traceback
            traceback.print_exc()
            return self._json(500, {"error": "internal error"})

    def _report_builder(self):
        if getattr(self, "_rb", None) is None:
            self._rb = _load_report_builder(self.project_dir)
        return self._rb

    _ASSETS = {"logo.png": "image/png", "clilogo.png": "image/png"}

    def _serve_asset(self, path):
        name = path.rsplit("/", 1)[-1]                 # basename only — no traversal
        ctype = self._ASSETS.get(name)
        if not ctype:
            return self._json(404, {"error": "no such asset"})
        try:
            data = (self.project_dir / "atpt" / "assets" / name).read_bytes()
        except Exception:
            return self._json(404, {"error": "asset missing"})
        return 200, ctype, data, {"Cache-Control": "max-age=86400"}

    def _route(self, method, path, query, body):
        if method == "GET" and path in ("/", "/index.html"):
            return 200, "text/html; charset=utf-8", INDEX_HTML.encode(), {}
        if method == "GET" and (path.startswith("/assets/") or path == "/favicon.ico"):
            return self._serve_asset("/assets/logo.png" if path == "/favicon.ico" else path)

        data = {}
        if method == "POST" and body:
            try:
                data = json.loads(body)
            except Exception:
                return self._json(400, {"error": "invalid JSON body"})
            if not isinstance(data, dict):
                return self._json(400, {"error": "JSON body must be an object"})

        if path == "/api/engagements" and method == "GET":
            return self._json(200, {"engagements": self._store().list_engagements()})
        if path == "/api/engagement" and method == "POST":
            return self._create_engagement(data)
        if path == "/api/demo" and method == "POST":
            return self._create_demo()

        # --- global settings & providers (no engagement required) -----------
        if path == "/api/settings":
            if method == "GET":
                return self._json(200, _redact_settings(self._store().get_settings()))
            if method == "POST":
                return self._save_settings(data)
        if path == "/api/settings/sudo-password":
            if method != "POST":
                return self._json(405, {"error": "POST only; this value is never read back"})
            privilege.set_password(data.get("password") or "")
            return self._json(200, {"ok": True, "has_password": privilege.has_password()})
        if path == "/api/providers/status" and method == "GET":
            return self._json(200, {"providers": [
                {"name": n, **providers.status(n)} for n in providers.known()]})
        if path == "/api/providers/install" and method == "POST":
            return self._provider_install(data)
        if path == "/api/providers/login" and method == "POST":
            return self._provider_login(data)

        eid = query.get("eng") or data.get("eng")
        if path.startswith("/api/") and not eid:
            return self._json(400, {"error": "missing 'eng' (engagement id)"})
        store = self._store()
        if not store.get_engagement(eid):
            return self._json(404, {"error": "no such engagement"})

        if path == "/api/status" and method == "GET":
            return self._json(200, self._status_obj(store, eid))
        if path == "/api/findings" and method == "GET":
            rows = [{**f, "evidence": _parse_evidence(f)} for f in store.list_findings(eid)]
            return self._json(200, {"findings": rows})
        if path == "/api/tree" and method == "GET":
            return self._json(200, self._tree(store, eid))
        if path == "/api/run" and method == "POST":
            mode = data.get("mode") or store.get_engagement(eid)["mode"]
            res = self._orch(store).run(store.get_engagement(eid), mode, dry_run=bool(data.get("dry_run")))
            return self._json(200, {"result": res, "status": self._status_obj(store, eid)})
        if path == "/api/approve" and method == "POST":
            store.resolve_approval(eid, data.get("module"), "approved")
            store.add_event(eid, None, data.get("module"), "info", "approval_resolved",
                            f"module '{data.get('module')}' approved via UI", None)
            return self._json(200, {"status": self._status_obj(store, eid)})
        if path == "/api/chat" and method == "POST":
            return self._chat(store, eid, data.get("message", ""))
        if path == "/api/report" and method == "GET":
            md = self._report_builder()(store, eid, self.project_dir)
            return (200, "text/markdown; charset=utf-8", md.encode(),
                    {"Content-Disposition": f'attachment; filename="{eid}-ptes-report.md"'})
        if path == "/api/settings/ctf":
            if method == "GET":
                return self._json(200, self._get_ctf(store, eid))
            if method == "POST":
                return self._save_ctf(store, eid, data)

        return self._json(404, {"error": "no such route"})

    def _create_engagement(self, data):
        eid = (data.get("engagement") or "").strip()
        scope = data.get("scope") or {}
        has_target = bool(scope.get("in_scope_domains") or scope.get("in_scope_cidrs"))
        if not valid_eid(eid):
            return self._json(400, {"error": "engagement id must be 1-64 chars of [A-Za-z0-9_-]"})
        if not has_target:
            return self._json(400, {"error": "scope must define at least one in-scope domain or CIDR (target required)"})
        store = self._store()
        store.create_engagement(eid, data.get("name") or eid, scope, f"{eid}.scope.json",
                                data.get("mode") or "semi", {})
        store.add_event(eid, "scope", None, "info", "engagement_init",
                        f"engagement '{eid}' created via UI", None)
        return self._json(200, {"engagement": store.get_engagement(eid)})

    def _create_demo(self):
        store = self._store()
        eid = "demo"
        store.create_engagement(eid, "Demo Engagement",
                                {"in_scope_domains": ["demo.local"], "in_scope_cidrs": ["10.0.0.0/24"]},
                                "demo.scope.json", "semi", {})
        for a in (
            {"asset_type": "service", "value": "10.0.0.5:6379", "host": "10.0.0.5",
             "ip": "10.0.0.5", "port": 6379, "service": "redis"},
            {"asset_type": "service", "value": "10.0.0.5:22", "host": "10.0.0.5",
             "ip": "10.0.0.5", "port": 22, "service": "ssh"},
            {"asset_type": "web_endpoint", "value": "http://demo.local", "host": "demo.local",
             "url": "http://demo.local", "http_status": 200, "tech": ["nginx", "php"]},
            {"asset_type": "web_path", "value": "http://demo.local/admin", "host": "demo.local",
             "url": "http://demo.local/admin", "http_status": 200},
        ):
            store.upsert_asset(eid, a)
        store.add_event(eid, "recon", None, "info", "demo_seed",
                        "demo engagement seeded with 4 sample assets", None)
        return self._json(200, {"engagement": store.get_engagement(eid)})

    # ---- settings / providers / ctf ----------------------------------------
    def _save_settings(self, data):
        store = self._store()
        existing = store.get_settings()
        patch = _preserve_reasoning_keys(dict(data), existing)
        patch.pop("eng", None)
        store.set_settings(patch)
        if "sudo_allowed" in patch:
            privilege.set_allowed(bool(patch["sudo_allowed"]))
        return self._json(200, _redact_settings(store.get_settings()))

    def _provider_install(self, data):
        """Autonomous install: deps (Node/npm) + the CLI, all under sudo. The only
        input required from the operator is the sudo password (memory-only)."""
        name = (data.get("name") or "").strip()
        if not providers.get(name):
            return self._json(400, {"error": f"unknown provider '{name}' — install it yourself"})
        pw = data.get("sudo_password")
        if pw:
            privilege.set_password(pw)                 # remember in memory this session
        res = providers.run_install(name)              # uses the in-memory sudo password
        if res.get("needs_sudo"):
            return self._json(200, {"needs_sudo": True,
                                    "message": "sudo password required to install"})
        return self._json(200, res)

    def _provider_login(self, data):
        name = (data.get("name") or "").strip()
        entry = providers.get(name)
        argv = providers.login_argv(name)
        if not entry or not argv:
            return self._json(400, {"error": f"no login command for '{name}'"})
        command = " ".join(argv)
        if entry.get("login_interactive"):
            # a real TTY login can't be driven from the browser — hand it back.
            return self._json(200, {"mode": "terminal", "command": command,
                                    "help": entry.get("help", "")})
        # Non-interactive login (e.g. `codex login`) — run and surface output/URL.
        import subprocess
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=180)
            return self._json(200, {"mode": "ran", "command": command,
                                    "rc": p.returncode, "stdout": p.stdout[-4000:],
                                    "stderr": p.stderr[-2000:], "help": entry.get("help", "")})
        except Exception as exc:
            return self._json(200, {"mode": "terminal", "command": command,
                                    "help": entry.get("help", ""), "note": str(exc)})

    def _get_ctf(self, store, eid) -> dict:
        cfg = json.loads(store.get_engagement(eid).get("config") or "{}")
        ctf = dict(cfg.get("ctf") or {})
        ctf["attackbox_has_password"] = privilege.has_attackbox_password(eid)
        return ctf

    def _save_ctf(self, store, eid, data):
        patch = {}
        if "goals" in data:
            patch["goals"] = str(data.get("goals") or "")
        if "vpn_config_path" in data:
            vp = str(data.get("vpn_config_path") or "").strip()
            patch["vpn_config_path"] = vp
            if vp and not (vp.endswith(".ovpn") or vp.endswith(".conf")):
                store.add_event(eid, None, None, "warn", "ctf_vpn",
                                f"VPN path '{vp}' is not a .ovpn/.conf file", None)
        if "attackbox" in data:
            ab = data.get("attackbox") or {}
            host = str(ab.get("host") or "").strip()
            user = str(ab.get("user") or "").strip()
            pw = ab.get("password") or ""
            # Only require host+user when the operator is actually setting a box.
            if (host or user or pw or ab.get("key_path")) and not (host and user):
                return self._json(400, {"error": "attack-box requires both host and user"})
            box = {"host": host, "user": user}
            if ab.get("key_path"):
                box["key_path"] = str(ab["key_path"]).strip()
            patch["attackbox"] = box                       # NOTE: password excluded from storage
            privilege.set_attackbox_password(eid, pw)       # kept in memory only
        store.update_engagement_config(eid, {"ctf": patch})
        return self._json(200, self._get_ctf(store, eid))

    def _chat(self, store, eid, message):
        msg = (message or "").strip()
        low = msg.lower()
        events, reply = [], ""
        if low in ("help", "?", "עזרה", ""):
            reply = ("Commands: **run** [step|semi|full] · **plan** · **status** · "
                     "**approve <module>** · **report**. Or use the buttons.")
        elif low.startswith("status") or low.startswith("מצב"):
            s = self._status_obj(store, eid)
            reply = (f"assets={s['assets']} · candidates={s['candidates']} · "
                     f"validated={s['validated']} · false-positives={s['false_positives']} · "
                     f"pending approvals={len(s['pending_approvals'])}")
        elif low.startswith("plan"):
            mode = next((m for m in ("step", "semi", "full") if m in low), store.get_engagement(eid)["mode"])
            rows = self._orch(store).plan(store.get_engagement(eid), mode)
            reply = "Pending: " + (", ".join(f"{r['id']}({r['phase']})" for r in rows) or "nothing runnable")
        elif low.startswith("run") or low.startswith("רוץ"):
            mode = next((m for m in ("step", "semi", "full") if m in low), "semi")
            res = self._orch(store).run(store.get_engagement(eid), mode)
            reply = f"ran mode={mode}: executed {res['executed'] or '[]'}"
            if res.get("gated_on"):
                reply += f" · PAUSED before intrusive '{res['gated_on']}' — approve it to continue."
        elif low.startswith("approve"):
            parts = msg.split()
            if len(parts) >= 2:
                store.resolve_approval(eid, parts[1], "approved")
                store.add_event(eid, None, parts[1], "info", "approval_resolved",
                                f"module '{parts[1]}' approved via chat", None)
                reply = f"approved {_h(parts[1])} — send 'run' to continue."
            else:
                reply = "usage: approve <module-id>"
        elif low.startswith("report"):
            reply = "Report ready — use the **Download report** button (PTES Markdown)."
        else:
            reply = "Unrecognized. Try: run · plan · status · approve <module> · report."
        s = self._status_obj(store, eid)
        return self._json(200, {"reply": reply, "status": s})


def serve(project_dir, port=8787, host="127.0.0.1"):
    app = WebApp(project_dir)
    # DNS-rebinding defense: a localhost bind only answers to localhost Host headers.
    # An explicit wildcard bind (0.0.0.0) opts out — that exposure is documented.
    allowed_hosts = None if host in ("0.0.0.0", "::") else {"127.0.0.1", "localhost", host}

    class Handler(BaseHTTPRequestHandler):
        def _do(self, method):
            if allowed_hosts is not None:
                h = (self.headers.get("Host") or "").split(":")[0]
                if h not in allowed_hosts:
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            body = b""
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
            status, ctype, data, headers = app.handle(method, u.path, q, body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._do("GET")

        def do_POST(self):
            self._do("POST")

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"ATPTmaster console: http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATPTmaster Console</title>
<link rel="icon" type="image/png" href="/assets/logo.png">
<style>
:root{--bg:#0d1117;--panel:#161b22;--edge:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#2f81f7;--field:#0d1117;
--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#3fb950;--val:#3fb950;--cand:#d29922;--fp:#6e7681}
:root[data-theme=light]{--bg:#f6f8fa;--panel:#ffffff;--edge:#d0d7de;--fg:#1f2328;--mut:#59636e;--acc:#0969da;--field:#ffffff}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--edge);background:var(--panel)}
header b{font-size:16px}header .sp{flex:1}
select,input,button,textarea{font:inherit;color:var(--fg);background:var(--field);border:1px solid var(--edge);border-radius:6px;padding:6px 8px}
button{background:var(--acc);border-color:var(--acc);color:#fff;cursor:pointer}button.ghost{background:var(--field);color:var(--fg)}
button:hover{filter:brightness(1.1)}button:disabled{opacity:.5;cursor:not-allowed}
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px;max-width:1300px;margin:0 auto}
.col{display:flex;flex-direction:column;gap:12px;min-width:0}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:10px;padding:12px}
.card h3{margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
#chatlog{height:300px;overflow:auto;display:flex;flex-direction:column;gap:8px;padding-right:4px}
.msg{padding:8px 10px;border-radius:8px;max-width:90%}
.msg.me{align-self:flex-end;background:#1f6feb33;border:1px solid #1f6feb55}
.msg.sys{align-self:flex-start;background:var(--field);border:1px solid var(--edge)}
.msg.ev{align-self:stretch;background:transparent;border:0;color:var(--mut);font-family:ui-monospace,monospace;font-size:12px;padding:2px 4px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.chatbar{display:flex;gap:8px;margin-top:8px}.chatbar input{flex:1}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--edge);vertical-align:top}
th{color:var(--mut);font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:capitalize}
.sev-critical{background:#f8514922;color:var(--crit)}.sev-high{background:#ff7b7222;color:var(--high)}
.sev-medium{background:#d2992222;color:var(--med)}.sev-low{background:#3fb95022;color:var(--low)}.sev-info{background:#6e768122;color:var(--mut)}
.st-validated{color:var(--val)}.st-candidate{color:var(--cand)}.st-false_positive{color:var(--fp);text-decoration:line-through}
.tree .branch{margin-bottom:6px}.tree .dom{cursor:pointer;font-weight:600}.tree ul{margin:4px 0 8px 16px;padding:0;list-style:none}
.tree li{padding:2px 0;border-left:2px solid var(--edge);padding-left:10px;margin-left:2px}
.muted{color:var(--mut)}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}.grid2 label{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--mut)}
.stat{display:flex;gap:14px;flex-wrap:wrap}.stat b{font-size:18px}.stat div{display:flex;flex-direction:column}
.hidden{display:none!important}
.brandcard{display:flex;align-items:center;justify-content:center;background:#000;border-color:var(--edge);padding:18px}
.brandlogo{max-height:300px;max-width:100%;width:auto;display:block;filter:drop-shadow(0 0 12px rgba(47,129,247,.25))}
@media(max-width:900px){.wrap{grid-template-columns:1fr}.brandlogo{max-height:200px}}
/* settings modal */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:flex-start;justify-content:center;z-index:50;padding:24px;overflow:auto}
.sheet{background:var(--panel);border:1px solid var(--edge);border-radius:12px;width:100%;max-width:720px;display:flex;flex-direction:column;max-height:90vh}
.sheettop,.sheetbot{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--edge)}
.sheetbot{border-bottom:0;border-top:1px solid var(--edge);justify-content:flex-end}
.sheettop b{font-size:15px}.sheettop .sp{flex:1}
.tabs{display:flex;flex-wrap:wrap;gap:4px;padding:10px 12px 0}
.tab{background:transparent;border:1px solid transparent;color:var(--mut);border-radius:6px 6px 0 0;padding:6px 10px}
.tab.on{color:var(--fg);border-color:var(--edge);border-bottom-color:var(--panel);background:var(--field)}
.panels{padding:16px;overflow:auto}
.panel{display:flex;flex-direction:column;gap:10px}
.prow{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end;border:1px solid var(--edge);border-radius:8px;padding:10px}
.prow label{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--mut)}
.prow .full{grid-column:1/-1}
.hint{font-size:12px;color:var(--mut)}
.warn{color:var(--med);font-size:12px}
.ladder{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}
.ladder li{display:flex;align-items:center;gap:8px;border:1px solid var(--edge);border-radius:8px;padding:6px 10px}
.ladder li .nm{flex:1}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:999px;border:1px solid var(--edge);color:var(--mut)}
.badge.ok{color:var(--val);border-color:var(--val)}
.toggle{display:flex;align-items:center;gap:8px}
.toggle input{width:auto}
pre.out{background:var(--field);border:1px solid var(--edge);border-radius:6px;padding:8px;font-size:12px;white-space:pre-wrap;max-height:160px;overflow:auto}
</style></head>
<body>
<header>
  <b>🛡️ ATPTmaster</b><span class="muted">autonomous pentest console</span>
  <span class="sp"></span>
  <select id="engsel" title="engagement"></select>
  <select id="mode"><option value="step">step</option><option value="semi" selected>semi</option><option value="full">full</option></select>
  <label class="muted" style="display:flex;gap:4px;align-items:center"><input type="checkbox" id="dry" style="width:auto"> dry-run</label>
  <button id="runbtn">▶ Run</button>
  <button class="ghost" id="dlbtn">⬇ Download report</button>
  <button class="ghost" id="setbtn" title="Settings">⚙ Settings</button>
</header>

<div class="wrap">
  <div class="col">
    <div class="card brandcard"><img class="brandlogo" src="/assets/logo.png" alt="ATPTmaster"></div>
    <div class="card" id="newcard">
      <h3>1 · Define scope &amp; target</h3>
      <div class="grid2">
        <label>Engagement id<input id="f_id" placeholder="acme-2026"></label>
        <label>Name<input id="f_name" placeholder="Acme external"></label>
        <label>In-scope domains (comma)<input id="f_dom" placeholder="acme.com, api.acme.com"></label>
        <label>In-scope CIDRs (comma)<input id="f_cidr" placeholder="203.0.113.0/24"></label>
        <label>Out-of-scope (comma)<input id="f_out" placeholder="mail.acme.com"></label>
        <label>Default mode
          <select id="f_mode"><option>step</option><option selected>semi</option><option>full</option></select></label>
      </div>
      <div class="row" style="margin-top:8px">
        <button id="createbtn">Create engagement</button>
        <button class="ghost" id="demobtn">Load demo (no tools needed)</button>
        <span class="muted" id="createmsg"></span>
      </div>
    </div>

    <div class="card">
      <h3>2 · Chat control</h3>
      <div id="chatlog"></div>
      <div class="chatbar">
        <input id="chatin" placeholder="type: run · plan · status · approve <module> · report">
        <button id="sendbtn">Send</button>
      </div>
    </div>

    <div class="card">
      <h3>Status</h3>
      <div class="stat" id="stat"><span class="muted">no engagement selected</span></div>
      <div id="approvals" style="margin-top:8px"></div>
    </div>
  </div>

  <div class="col">
    <div class="card">
      <h3>Findings</h3>
      <div id="findings"><span class="muted">—</span></div>
    </div>
    <div class="card">
      <h3>Attack-direction tree</h3>
      <div class="tree" id="tree"><span class="muted">—</span></div>
    </div>
  </div>
</div>

<div id="settings" class="modal hidden">
  <div class="sheet">
    <div class="sheettop"><b>⚙ Settings</b><span class="sp"></span>
      <button class="ghost" id="setclose">✕</button></div>
    <div class="tabs">
      <button class="tab on" data-tab="providers">Providers (API key)</button>
      <button class="tab" data-tab="subs">Subscription CLI</button>
      <button class="tab" data-tab="ollama">Local LLM</button>
      <button class="tab" data-tab="ladder">Model ladder</button>
      <button class="tab" data-tab="operator">Operator</button>
      <button class="tab" data-tab="ctf">CTF</button>
    </div>
    <div class="panels">
      <div class="panel" data-panel="providers">
        <div class="hint">Hosted API providers. Choose <b>paste key</b> (stored on this machine) or <b>env var</b> (read from the environment at call time — nothing stored).</div>
        <div id="httpList"></div>
        <button class="ghost" id="addHttp">+ Add API provider</button>
      </div>
      <div class="panel hidden" data-panel="subs">
        <div class="hint">Subscription CLIs you're logged into. Claude, Gemini &amp; Codex are ready by default — press <b>Install (auto)</b> and it installs dependencies + the CLI for you (asks only for your sudo password). Or add your own with <b>+ Custom CLI</b>.</div>
        <div id="subList"></div>
        <button class="ghost" id="addSub">+ Custom CLI provider</button>
      </div>
      <div class="panel hidden" data-panel="ollama">
        <div class="hint">Local models via <b>Ollama</b>. Nothing leaves your machine.</div>
        <div id="ollamaList"></div>
        <button class="ghost" id="addOllama">+ Add local model</button>
      </div>
      <div class="panel hidden" data-panel="ladder">
        <div class="hint">Try providers top-to-bottom; fall back on error/refusal. Policy limits which run per phase.</div>
        <ul class="ladder" id="ladder"></ul>
        <div class="prow" style="grid-template-columns:1fr 1fr 1fr">
          <label>map policy<select id="pol_map"><option>any</option><option>hosted_ok</option><option>local_only</option></select></label>
          <label>exploit policy<select id="pol_exploit"><option>any</option><option>hosted_ok</option><option>local_only</option></select></label>
          <label>report policy<select id="pol_report"><option>any</option><option>hosted_ok</option><option>local_only</option></select></label>
        </div>
      </div>
      <div class="panel hidden" data-panel="operator">
        <div class="prow" style="grid-template-columns:1fr">
          <label class="full">Pentester name (appears on the report)<input id="s_name" placeholder="e.g. Avi Twil"></label>
        </div>
        <div class="prow" style="grid-template-columns:1fr">
          <div class="toggle"><input type="checkbox" id="s_theme"> <label for="s_theme" style="color:var(--fg)">Light theme</label></div>
        </div>
        <div class="prow" style="grid-template-columns:1fr">
          <div class="toggle"><input type="checkbox" id="s_sudo"> <label for="s_sudo" style="color:var(--fg)">Allow sudo (privileged scans)</label></div>
          <div id="sudoPwWrap" class="full hidden">
            <label class="hint">Sudo password (kept in memory only, never saved to disk, re-asked after restart)
              <input type="password" id="s_sudopw" placeholder="••••••••" autocomplete="off"></label>
            <button class="ghost" id="sudoPwBtn" style="margin-top:6px">Set sudo password</button>
            <span class="hint" id="sudoPwMsg"></span>
          </div>
        </div>
      </div>
      <div class="panel hidden" data-panel="ctf">
        <div class="hint" id="ctfEng">Applies to the selected engagement.</div>
        <label class="hint full">Goals — what the LLM should look for<textarea id="c_goals" rows="3" placeholder="e.g. find user.txt and root.txt; enumerate web + SSH"></textarea></label>
        <label class="hint">VPN config file (path on this machine)<input id="c_vpn" placeholder="/home/kali/htb.ovpn"></label>
        <div class="prow full">
          <label>Attack-box host<input id="c_ab_host" placeholder="10.10.14.1"></label>
          <label>Attack-box user<input id="c_ab_user" placeholder="kali"></label>
          <label class="full">Attack-box password (memory only) or key path below
            <input type="password" id="c_ab_pw" autocomplete="off" placeholder="••••••••"></label>
          <label class="full">SSH key path (optional, stored)<input id="c_ab_key" placeholder="/home/kali/.ssh/id_ed25519"></label>
        </div>
        <button class="ghost" id="ctfSave">Save CTF settings</button>
        <span class="hint" id="ctfMsg"></span>
      </div>
    </div>
    <div class="sheetbot"><span class="hint" id="setmsg"></span>
      <button id="setsave">Save settings</button></div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s), api=(p,o)=>fetch(p,o).then(r=>r.json());
let ENG=null;
const eng=()=>ENG;
function esc(s){return (s==null?'':''+s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
const SEVS=['critical','high','medium','low','info'],STATS=['candidate','validated','false_positive'];
const sevCls=s=>SEVS.includes((s||'').toLowerCase())?(''+s).toLowerCase():'info';
const stCls=s=>STATS.includes(s)?s:'candidate';
function chat(cls,html){const d=document.createElement('div');d.className='msg '+cls;d.innerHTML=html;$('#chatlog').appendChild(d);$('#chatlog').scrollTop=1e9}

async function refreshEngagements(sel){
  const {engagements}=await api('/api/engagements');
  const s=$('#engsel');s.innerHTML='';
  engagements.forEach(e=>{const o=document.createElement('option');o.value=e.id;o.textContent=e.id+' — '+(e.name||'');s.appendChild(o)});
  if(sel){s.value=sel}
  ENG=s.value||null;
  if(ENG)await refreshAll();
}
async function refreshAll(){ if(!ENG)return; await Promise.all([refreshStatus(),refreshFindings(),refreshTree()]); }

async function refreshStatus(){
  const s=await api('/api/status?eng='+encodeURIComponent(ENG));
  $('#stat').innerHTML=`<div><b>${s.assets}</b><span class=muted>assets</span></div>
    <div><b>${s.candidates}</b><span class=muted>candidates</span></div>
    <div><b style="color:var(--val)">${s.validated}</b><span class=muted>validated</span></div>
    <div><b>${s.false_positives}</b><span class=muted>false-pos</span></div>`;
  const ap=$('#approvals');
  if(s.pending_approvals&&s.pending_approvals.length){
    ap.innerHTML='<div class=muted>Pending approvals (intrusive):</div>'+s.pending_approvals.map(a=>
      `<div class=row style="margin-top:4px"><span>${esc(a.module)} <span class=muted>(${esc(a.phase)})</span></span>
       <button class=approve data-m="${esc(a.module)}">Approve</button></div>`).join('');
    ap.querySelectorAll('.approve').forEach(b=>b.onclick=async()=>{
      await api('/api/approve',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({eng:ENG,module:b.dataset.m})});
      chat('sys','Approved <b>'+esc(b.dataset.m)+'</b>. Send <b>run</b> to continue.');refreshAll();});
  } else ap.innerHTML='';
  // stream latest events into chat log (replace ev lines)
  document.querySelectorAll('.msg.ev').forEach(e=>e.remove());
  (s.events||[]).slice(-12).forEach(e=>chat('ev',`[${esc(e.phase||'')}/${esc(e.module||'')}] ${esc(e.message)}`));
}
async function refreshFindings(){
  const {findings}=await api('/api/findings?eng='+encodeURIComponent(ENG));
  if(!findings.length){$('#findings').innerHTML='<span class=muted>No findings yet — run the pipeline.</span>';return}
  const rows=findings.map(f=>`<tr><td><span class="pill sev-${sevCls(f.severity)}">${esc(f.severity||'info')}</span></td>
    <td>${esc(f.title)}<div class=muted style="font-size:11px">${esc((f.evidence&&f.evidence.asset_value)||f.source_tool||'')}</div></td>
    <td class="st-${stCls(f.status)}">${esc(f.status)}</td><td>${esc(f.owasp||'—')}</td><td>${esc(f.cvss??'—')}</td></tr>`).join('');
  $('#findings').innerHTML=`<table><tr><th>Sev</th><th>Finding</th><th>Status</th><th>OWASP</th><th>CVSS</th></tr>${rows}</table>`;
}
async function refreshTree(){
  const t=await api('/api/tree?eng='+encodeURIComponent(ENG));
  if(!t.branches||!t.branches.length){$('#tree').innerHTML='<span class=muted>—</span>';return}
  $('#tree').innerHTML=`<div class=muted>🎯 ${esc(t.target)}</div>`+t.branches.map(b=>
    `<div class=branch><div class=dom>▸ ${esc(b.domain)} <span class=muted>(${b.findings.length})</span></div>
     <ul>${b.findings.map(f=>`<li><span class="pill sev-${sevCls(f.severity)}">${esc(f.severity)}</span>
       ${esc(f.title)} <span class="st-${stCls(f.status)} muted">${esc(f.status)}</span></li>`).join('')}</ul></div>`).join('');
}

$('#createbtn').onclick=async()=>{
  const scope={in_scope_domains:split($('#f_dom').value),in_scope_cidrs:split($('#f_cidr').value),out_of_scope:split($('#f_out').value)};
  const r=await api('/api/engagement',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({engagement:$('#f_id').value.trim(),name:$('#f_name').value.trim(),scope,mode:$('#f_mode').value})});
  if(r.error){$('#createmsg').textContent='⚠ '+r.error;return}
  $('#createmsg').textContent='';chat('sys','Engagement <b>'+esc(r.engagement.id)+'</b> created. Scope locked. Send <b>run</b>.');
  await refreshEngagements(r.engagement.id);
};
$('#demobtn').onclick=async()=>{
  const r=await api('/api/demo',{method:'POST'});
  chat('sys','Loaded <b>demo</b> engagement (4 seeded assets). Send <b>run full</b> to map → validate → report.');
  await refreshEngagements(r.engagement.id);
};
function split(v){return (v||'').split(',').map(x=>x.trim()).filter(Boolean)}

async function send(){
  const v=$('#chatin').value.trim(); if(!v||!ENG)return; $('#chatin').value='';
  chat('me',esc(v));
  const r=await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({eng:ENG,message:v})});
  if(r.error){chat('sys','⚠ '+esc(r.error));return}
  chat('sys',r.reply);await refreshAll();
}
$('#sendbtn').onclick=send;$('#chatin').addEventListener('keydown',e=>{if(e.key==='Enter')send()});
$('#runbtn').onclick=async()=>{
  if(!ENG){chat('sys','Create or select an engagement first.');return}
  const r=await api('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({eng:ENG,mode:$('#mode').value,dry_run:$('#dry').checked})});
  chat('sys','Ran <b>'+$('#mode').value+'</b>'+($('#dry').checked?' (dry-run)':'')+': executed '+JSON.stringify(r.result.executed)+
    (r.result.gated_on?' · ⏸ paused before <b>'+esc(r.result.gated_on)+'</b> (approve to continue)':''));
  await refreshAll();
};
$('#dlbtn').onclick=()=>{ if(!ENG){chat('sys','No engagement selected.');return} window.location='/api/report?eng='+encodeURIComponent(ENG); };
$('#engsel').onchange=async()=>{ENG=$('#engsel').value;await refreshAll()};

/* ===== Settings ===== */
let SET={}, HTTP=[], SUB=[], OLLAMA=[], PREF=[], PSTATUS={};
function applyTheme(light){document.documentElement.setAttribute('data-theme',light?'light':'dark');}
try{applyTheme(localStorage.getItem('atpt_theme')==='light');}catch(e){}

function decompose(){
  HTTP=[];SUB=[];OLLAMA=[];
  const r=SET.reasoning||{}, provs=r.providers||{};
  const KNOWN=Object.keys(PSTATUS);
  for(const [name,p] of Object.entries(provs)){
    const b=p.backend;
    if(b==='http_api')HTTP.push({name,api:p.api||'openai',model:p.model||'',endpoint:p.endpoint||'',mode:p.key_env?'env':'paste',key:p.key_env||'',has_key:!!p.has_key});
    else if(b==='cli')SUB.push({name,cmd:p.cmd||name,custom:!KNOWN.includes(name)});
    else if(b==='ollama')OLLAMA.push({name,model:p.model||'llama3.1',endpoint:p.endpoint||''});
  }
  // Always surface all known CLIs as default rows (claude, gemini, codex).
  KNOWN.forEach(n=>{ if(!SUB.some(x=>!x.custom&&x.name===n)) SUB.push({name:n,cmd:(PSTATUS[n]||{}).cmd||'',custom:false}); });
  PREF=(r.preference||[]).slice();
  const pol=r.policy||{};
  $('#pol_map').value=pol.map||'any';$('#pol_exploit').value=pol.exploit||'any';$('#pol_report').value=pol.report||'any';
}
function allNames(){return [...HTTP,...SUB,...OLLAMA].map(p=>p.name).filter(Boolean);}
function reconcilePref(){const names=allNames();PREF=PREF.filter(n=>names.includes(n));names.forEach(n=>{if(!PREF.includes(n))PREF.push(n);});}

function httpRow(p,i){return `<div class="prow" data-i="${i}" data-kind="http" style="grid-template-columns:1fr 1fr">
  <label>Name<input class="f_name" value="${esc(p.name)}"></label>
  <label>API<select class="f_api"><option value="anthropic"${p.api==='anthropic'?' selected':''}>anthropic</option><option value="openai"${p.api!=='anthropic'?' selected':''}>openai</option></select></label>
  <label>Model<input class="f_model" value="${esc(p.model)}" placeholder="gpt-5 / claude-opus-5"></label>
  <label>Key mode<select class="f_mode"><option value="paste"${p.mode==='paste'?' selected':''}>paste key</option><option value="env"${p.mode==='env'?' selected':''}>env var</option></select></label>
  <label class="full">Endpoint (optional)<input class="f_ep" value="${esc(p.endpoint)}" placeholder="https://api.openai.com/v1/chat/completions"></label>
  <label class="full">${p.mode==='env'?'Env var name':'API key'} <input class="f_key" type="${p.mode==='env'?'text':'password'}" autocomplete="off" value="${p.mode==='env'?esc(p.key):''}" placeholder="${p.mode==='env'?'ANTHROPIC_API_KEY':(p.has_key?'•••••• stored — blank keeps it':'paste secret')}"></label>
  <button class="ghost f_del full">Remove</button></div>`;}
function subRow(p,i){
  const s=p.custom?null:PSTATUS[p.name]; const inst=s&&s.installed;
  const head=p.custom
    ? `<label>Name<input class="f_name" value="${esc(p.name)}" placeholder="my-cli"></label>
       <label class="full">Command (full path)<input class="f_cmd" value="${esc(p.cmd)}" placeholder="/usr/bin/mycli -p"></label>`
    : `<label>Provider<input value="${esc(s?s.label:p.name)}" readonly></label>
       <label class="full">Reasoning command (auto)<input class="f_cmd" value="${esc(p.cmd||(s&&s.cmd)||'')}" readonly></label>`;
  return `<div class="prow" data-i="${i}" data-kind="sub" data-name="${esc(p.name)}" data-custom="${p.custom?1:0}" style="grid-template-columns:1fr 1fr">
  ${head}
  <div class="full row">${s?`<span class="badge ${inst?'ok':''}">${inst?'installed':'not installed'}</span>`:'<span class="hint">custom command</span>'}
    ${(s&&!inst)?`<button class="ghost f_install">⬇ Install (auto)</button>`:''}
    ${(s&&inst)?`<button class="ghost f_login">Log in</button>`:''}
    <span class="hint f_out"></span></div>
  <div class="full f_sudo hidden">
    <label class="hint">sudo password — needed to install dependencies &amp; the CLI (memory only, not saved)
      <input type="password" class="f_sudopw" autocomplete="off" placeholder="••••••••"></label>
    <button class="ghost f_sudogo" style="margin-top:6px">Install with sudo</button>
  </div>
  <button class="ghost f_del full">Remove</button></div>`;}
function ollamaRow(p,i){return `<div class="prow" data-i="${i}" data-kind="ollama" style="grid-template-columns:1fr 1fr">
  <label>Name<input class="f_name" value="${esc(p.name)}"></label>
  <label>Model<input class="f_model" value="${esc(p.model)}" placeholder="llama3.1"></label>
  <label class="full">Endpoint<input class="f_ep" value="${esc(p.endpoint)}" placeholder="http://localhost:11434/api/generate"></label>
  <button class="ghost f_del full">Remove</button></div>`;}

function renderProviders(){
  $('#httpList').innerHTML=HTTP.map(httpRow).join('')||'<div class=hint>No API providers yet.</div>';
  $('#subList').innerHTML=SUB.map(subRow).join('')||'<div class=hint>No CLI providers yet.</div>';
  $('#ollamaList').innerHTML=OLLAMA.map(ollamaRow).join('')||'<div class=hint>No local models yet.</div>';
  wireRows();
}
function renderLadder(){
  reconcilePref();
  $('#ladder').innerHTML=PREF.map((n,i)=>`<li data-n="${esc(n)}"><span class="nm">${i+1}. ${esc(n)}</span>
    <button class="ghost l_up" ${i===0?'disabled':''}>↑</button>
    <button class="ghost l_down" ${i===PREF.length-1?'disabled':''}>↓</button></li>`).join('')||'<div class=hint>Add providers first.</div>';
  $('#ladder').querySelectorAll('.l_up').forEach((b,idx)=>{const li=b.closest('li');b.onclick=()=>{const i=PREF.indexOf(li.dataset.n);if(i>0){[PREF[i-1],PREF[i]]=[PREF[i],PREF[i-1]];renderLadder();}};});
  $('#ladder').querySelectorAll('.l_down').forEach(b=>{const li=b.closest('li');b.onclick=()=>{const i=PREF.indexOf(li.dataset.n);if(i<PREF.length-1){[PREF[i+1],PREF[i]]=[PREF[i],PREF[i+1]];renderLadder();}};});
}
function syncFromDom(){
  const rd=(row,cls)=>{const e=row.querySelector(cls);return e?e.value.trim():'';};
  HTTP=[...document.querySelectorAll('.prow[data-kind=http]')].map(row=>{
    const mode=rd(row,'.f_mode');const keyv=row.querySelector('.f_key').value;
    return {name:rd(row,'.f_name'),api:rd(row,'.f_api'),model:rd(row,'.f_model'),endpoint:rd(row,'.f_ep'),
            mode,key:keyv,has_key:HTTP.find(h=>h.name===rd(row,'.f_name'))?.has_key||false};});
  SUB=[...document.querySelectorAll('.prow[data-kind=sub]')].map(row=>{
    if(row.dataset.custom==='1') return {name:rd(row,'.f_name'),cmd:rd(row,'.f_cmd'),custom:true};
    return {name:row.dataset.name,cmd:rd(row,'.f_cmd')||((PSTATUS[row.dataset.name]||{}).cmd||''),custom:false};});
  OLLAMA=[...document.querySelectorAll('.prow[data-kind=ollama]')].map(row=>({name:rd(row,'.f_name'),model:rd(row,'.f_model'),endpoint:rd(row,'.f_ep')}));
}
function wireRows(){
  document.querySelectorAll('.f_del').forEach(b=>b.onclick=()=>{syncFromDom();const row=b.closest('.prow');const k=row.dataset.kind,i=+row.dataset.i;
    ({http:HTTP,sub:SUB,ollama:OLLAMA}[k]).splice(i,1);renderProviders();});
  document.querySelectorAll('.f_mode').forEach(s=>s.onchange=()=>{syncFromDom();renderProviders();});
  async function doInstall(row,pw){
    const name=row.dataset.name; const out=row.querySelector('.f_out');
    out.textContent='installing '+name+'… (dependencies + CLI; this can take a minute)';
    const body=pw?{name,sudo_password:pw}:{name};
    const r=await api('/api/providers/install',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(r.needs_sudo){ row.querySelector('.f_sudo').classList.remove('hidden');
      out.textContent='enter your sudo password to install'; return; }
    if(r.ok){ out.textContent='installed ✓'; row.querySelector('.f_sudo').classList.add('hidden');
      syncFromDom(); const i=+row.dataset.i; if(SUB[i]&&r.cmd)SUB[i].cmd=r.cmd;   // pin resolved bin path
      await loadStatuses(); renderProviders();
    } else { out.innerHTML='⚠ '+esc(r.failed||r.error||'install failed')+(r.log?'<br><span class=hint>'+esc((''+r.log).slice(-400))+'</span>':''); }
  }
  document.querySelectorAll('.f_install').forEach(b=>b.onclick=()=>doInstall(b.closest('.prow'),null));
  document.querySelectorAll('.f_sudogo').forEach(b=>b.onclick=()=>{
    const row=b.closest('.prow'); doInstall(row,row.querySelector('.f_sudopw').value); });
  document.querySelectorAll('.f_login').forEach(b=>b.onclick=async()=>{
    const row=b.closest('.prow');const name=row.dataset.name;const out=row.querySelector('.f_out');
    out.textContent='starting login…';
    const r=await api('/api/providers/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
    if(r.mode==='terminal')out.innerHTML='run in your terminal: <code>'+esc(r.command)+'</code>'+(r.help?' — '+esc(r.help):'');
    else out.textContent=(r.stdout||r.help||'login started').slice(0,200);});
}
async function loadStatuses(){const r=await api('/api/providers/status');PSTATUS={};(r.providers||[]).forEach(p=>PSTATUS[p.name]=p);}

function showTab(t){document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x.dataset.tab===t));
  document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('hidden',x.dataset.panel!==t));
  if(t==='ladder')renderLadder();}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{if(!['operator','ctf'].includes(b.dataset.tab))syncFromDom();showTab(b.dataset.tab);});

async function openSettings(){
  SET=await api('/api/settings');
  await loadStatuses();                 // need known-CLI list before decomposing
  decompose();
  $('#s_name').value=SET.pentester_name||'';
  $('#s_sudo').checked=!!SET.sudo_allowed;$('#sudoPwWrap').classList.toggle('hidden',!SET.sudo_allowed);
  let light=false;try{light=localStorage.getItem('atpt_theme')==='light';}catch(e){}$('#s_theme').checked=light;
  renderProviders();renderLadder();
  await loadCtf();
  showTab('providers');
  $('#settings').classList.remove('hidden');
}
function providersMap(){
  const m={};
  HTTP.forEach(p=>{if(!p.name)return;const c={backend:'http_api',api:p.api,model:p.model};if(p.endpoint)c.endpoint=p.endpoint;
    if(p.mode==='env'){if(p.key)c.key_env=p.key;} else {if(p.key)c.api_key=p.key;}m[p.name]=c;});
  SUB.forEach(p=>{if(!p.name)return;m[p.name]={backend:'cli',cmd:p.cmd||p.name};});
  OLLAMA.forEach(p=>{if(!p.name)return;const c={backend:'ollama',model:p.model||'llama3.1'};if(p.endpoint)c.endpoint=p.endpoint;m[p.name]=c;});
  return m;
}
$('#setsave').onclick=async()=>{
  syncFromDom();reconcilePref();
  const reasoning={providers:providersMap(),preference:PREF,
    policy:{map:$('#pol_map').value,exploit:$('#pol_exploit').value,report:$('#pol_report').value}};
  const body={pentester_name:$('#s_name').value.trim(),sudo_allowed:$('#s_sudo').checked,reasoning};
  const r=await api('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  SET=r;decompose();renderProviders();
  $('#setmsg').textContent='Saved ✓';setTimeout(()=>$('#setmsg').textContent='',1500);
};
$('#s_theme').onchange=()=>{applyTheme($('#s_theme').checked);try{localStorage.setItem('atpt_theme',$('#s_theme').checked?'light':'dark');}catch(e){}};
$('#s_sudo').onchange=()=>$('#sudoPwWrap').classList.toggle('hidden',!$('#s_sudo').checked);
$('#sudoPwBtn').onclick=async()=>{
  const pw=$('#s_sudopw').value;
  const r=await api('/api/settings/sudo-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  $('#s_sudopw').value='';$('#sudoPwMsg').textContent=r.has_password?'set for this session ✓':'cleared';};
$('#addHttp').onclick=()=>{syncFromDom();HTTP.push({name:'',api:'openai',model:'',endpoint:'',mode:'paste',key:'',has_key:false});renderProviders();};
$('#addSub').onclick=()=>{syncFromDom();SUB.push({name:'',cmd:'',custom:true});renderProviders();};
$('#addOllama').onclick=()=>{syncFromDom();OLLAMA.push({name:'',model:'llama3.1',endpoint:''});renderProviders();};

async function loadCtf(){
  $('#ctfEng').textContent=ENG?('Applies to engagement: '+ENG):'Select or create an engagement first.';
  ['#c_goals','#c_vpn','#c_ab_host','#c_ab_user','#c_ab_pw','#c_ab_key'].forEach(s=>$(s).value='');
  if(!ENG)return;
  const c=await api('/api/settings/ctf?eng='+encodeURIComponent(ENG));
  $('#c_goals').value=c.goals||'';$('#c_vpn').value=c.vpn_config_path||'';
  const ab=c.attackbox||{};$('#c_ab_host').value=ab.host||'';$('#c_ab_user').value=ab.user||'';$('#c_ab_key').value=ab.key_path||'';
  $('#c_ab_pw').placeholder=c.attackbox_has_password?'•••••• set this session':'••••••••';
}
$('#ctfSave').onclick=async()=>{
  if(!ENG){$('#ctfMsg').textContent='no engagement selected';return;}
  const body={goals:$('#c_goals').value,vpn_config_path:$('#c_vpn').value.trim(),
    attackbox:{host:$('#c_ab_host').value.trim(),user:$('#c_ab_user').value.trim(),
               password:$('#c_ab_pw').value,key_path:$('#c_ab_key').value.trim()}};
  const r=await api('/api/settings/ctf?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.error){$('#ctfMsg').textContent='⚠ '+r.error;return;}
  $('#c_ab_pw').value='';$('#ctfMsg').textContent='Saved ✓';setTimeout(()=>$('#ctfMsg').textContent='',1500);
};
$('#setbtn').onclick=openSettings;
$('#setclose').onclick=()=>$('#settings').classList.add('hidden');
$('#settings').onclick=e=>{if(e.target.id==='settings')$('#settings').classList.add('hidden');};

chat('sys','Welcome. Step 1: define scope &amp; target (or <b>Load demo</b>). Step 2: <b>run</b>. Then download the PTES report.');
refreshEngagements();
setInterval(()=>{if(ENG)refreshStatus()},2500);
</script>
</body></html>"""
