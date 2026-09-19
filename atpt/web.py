"""Stdlib web UI for ATPTmaster — chat-driven control + findings + attack tree +
PTES report download. No third-party deps: http.server + a single embedded page.

Routing lives in `WebApp.handle(method, path, query, body) -> (status, ctype, bytes, headers)`
so it is unit-testable without opening a socket. `serve()` wraps it in a threading
HTTP server; each request opens its own SQLite connection (thread-safe by construction).
Binds to 127.0.0.1 by default — this is an operator console, not a public endpoint.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import models, privilege, providers, selfupdate, vpn
from .config import offensive_agent_on
from .engine import Orchestrator
from .registry import discover
from .state import SQLiteStore
from .toolbox import Toolbox

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Background run control (stop-between-steps). eid -> {halt: Event, status, last}.
_RUNS: dict = {}
_RUNS_LOCK = threading.Lock()
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


_SCOPE_HOST_DOMAINS = {"web", "api", "ai", "cloud"}   # host/domain-based
# infra -> CIDRs; mobile/wireless -> metadata only (not host-enforceable)


def _derive_scope(scope: dict) -> dict:
    """Compute the flat oracle fields (in_scope_domains / in_scope_cidrs /
    out_of_scope / out_of_scope_cidrs) from a structured `domains` block, so the
    scope oracle keeps working while the UI edits per-domain rules. Legacy flat
    scopes (no `domains`) pass through unchanged."""
    doms = scope.get("domains") or {}
    if not doms:
        return scope
    d_in = list(scope.get("in_scope_domains") or [])
    c_in = list(scope.get("in_scope_cidrs") or [])
    d_out = list(scope.get("out_of_scope") or [])
    c_out = list(scope.get("out_of_scope_cidrs") or [])
    for key, d in doms.items():
        if not isinstance(d, dict) or not d.get("enabled"):
            continue
        ins = [x for x in (d.get("in") or []) if x]
        outs = [x for x in (d.get("out") or []) if x]
        if key == "infra":
            c_in += ins
            c_out += outs
        elif key in _SCOPE_HOST_DOMAINS:
            d_in += ins
            d_out += outs
        # mobile / wireless: stored in `domains`, not host-enforceable
    out = dict(scope)
    out["in_scope_domains"] = sorted(set(d_in))
    out["in_scope_cidrs"] = sorted(set(c_in))
    out["out_of_scope"] = sorted(set(d_out))
    out["out_of_scope_cidrs"] = sorted(set(c_out))
    return out


def _scope_confirm_payload(scope: dict) -> dict:
    """The normalized in-scope targets the offensive agent will operate against,
    plus a stable hash. The run start returns this for a one-time human
    confirmation (catches typos) before any action, in every mode."""
    flat = _derive_scope(scope or {})
    targets = sorted(set((flat.get("in_scope_cidrs") or []) + (flat.get("in_scope_domains") or [])))
    h = hashlib.sha256("\n".join(targets).encode()).hexdigest()
    return {"targets": targets, "hash": h}


def _enabled_without_target(scope: dict) -> list:
    """Return the keys of scope categories that are selected (enabled) but carry
    no concrete in-scope input. Such a category must not be scanned as "the full
    domain" — the operator has to name a target. Legacy flat scopes (no `domains`
    block) have no categories to check and return []."""
    doms = (scope or {}).get("domains") or {}
    empty = []
    for key, d in doms.items():
        if not (isinstance(d, dict) and d.get("enabled")):
            continue
        # a concrete target is any entry that is not blank and not the "whole
        # domain" sentinel ('all' / '*') — those mean "everything", which is what
        # we refuse to assume on the user's behalf.
        concrete = [x for x in (d.get("in") or [])
                    if str(x).strip() and str(x).strip().lower() not in ("all", "*")]
        if not concrete:
            empty.append(key)
    return sorted(empty)


def _pingable_targets(scope_json) -> list:
    """Single in-scope hosts we can reachability-probe: domains and bare IPs / /32
    CIDRs. Multi-host ranges (e.g. a /24) are skipped — there's no single address
    to ping. Returns [] on any parse trouble (probe is best-effort)."""
    import ipaddress
    try:
        scope = json.loads(scope_json) if isinstance(scope_json, str) else (scope_json or {})
    except Exception:
        return []
    out = []
    for d in scope.get("in_scope_domains") or []:
        d = str(d).strip()
        if d and d.lower() not in ("all", "*"):
            out.append(d)
    for c in scope.get("in_scope_cidrs") or []:
        c = str(c).strip()
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.num_addresses == 1:
                out.append(str(net.network_address))
        except ValueError:
            if c and c.lower() not in ("all", "*"):
                out.append(c)
    seen, uniq = set(), []
    for h in out:
        if h not in seen:
            seen.add(h); uniq.append(h)
    return uniq


def _wait_target_reachable(hosts, timeout: float = 45.0) -> bool:
    """Poll until any host answers an ICMP echo, or the timeout elapses. Uses the
    unprivileged `ping` binary (one packet, short wait). Returns True on the first
    reply. Best-effort: a box that blocks ping simply times out here (caller warns
    and scans anyway)."""
    import subprocess
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for h in hosts:
            try:
                r = subprocess.run(["ping", "-c", "1", "-W", "2", h],
                                   capture_output=True, timeout=4)
                if r.returncode == 0:
                    return True
            except Exception:
                pass
        time.sleep(2)
    return False


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

    # ---- background run control (stop-between-steps) ------------------------
    def _run_status(self, eid) -> dict:
        with _RUNS_LOCK:
            r = _RUNS.get(eid)
            return {"status": r["status"], "last": r.get("last")} if r else {"status": "idle"}

    def _start_run(self, eid, mode, vpn_path=None):
        with _RUNS_LOCK:
            r = _RUNS.get(eid)
            if r and r["status"] == "running":
                return self._json(200, {"status": "running", "already": True})
            halt = threading.Event()
            _RUNS[eid] = {"halt": halt, "status": "running", "last": None}

        def worker():
            store = self._store()
            eng = store.get_engagement(eid)
            try:
                # RUN owns the tunnel: bring it up and wait for it before scanning,
                # so recon never runs against a route that isn't connected yet.
                if vpn_path and not vpn.is_up():
                    store.add_event(eid, None, None, "info", "vpn_connect",
                                    f"bringing up VPN ({vpn_path})…", None)
                    cres = vpn.connect(vpn_path, privilege.current_password())
                    if not cres.get("ok"):
                        raise RuntimeError(f"VPN failed to start: {cres.get('error')}")
                    if not vpn.wait_connected(timeout=30):
                        raise RuntimeError(
                            f"VPN did not connect: {vpn.status().get('error') or 'timeout'}")
                    store.add_event(eid, None, None, "info", "vpn_connect",
                                    "VPN connected — starting run", None)
                    # The tunnel reports "connected" the moment openvpn finishes its
                    # init — but pushed routes (and a freshly-deployed lab box that is
                    # still booting) may not answer yet. Scanning now would find 0
                    # ports and the whole run would silently produce nothing. Wait for
                    # a target to actually respond; if none does, say so plainly.
                    hosts = _pingable_targets(eng.get("scope"))
                    if hosts and not _wait_target_reachable(hosts, timeout=45):
                        store.add_event(eid, "recon", None, "warn", "target_unreachable",
                            f"VPN is up but no in-scope target answered in 45s "
                            f"({', '.join(hosts)}) — the box may still be booting or "
                            f"blocks ping; scanning anyway", None)
                res = self._orch(store).run(eng, mode, control=lambda: not halt.is_set())
            except Exception as exc:
                store.add_event(eid, None, None, "error", "run_error", str(exc), None)
                res = {"executed": [], "error": str(exc)}
            with _RUNS_LOCK:
                paused = _RUNS.get(eid, {}).get("_pause")
                st = ("paused" if (halt.is_set() and paused) else
                      "stopped" if halt.is_set() else
                      "gated" if res.get("gated_on") else "done")
                _RUNS[eid] = {"halt": halt, "status": st, "last": res}

        t = threading.Thread(target=worker, daemon=True)
        with _RUNS_LOCK:
            _RUNS[eid]["thread"] = t
        t.start()
        return self._json(200, {"status": "running", "started": True})

    def _control_run(self, eid, action):
        with _RUNS_LOCK:
            r = _RUNS.get(eid)
            if not r or r["status"] != "running":
                return self._json(200, {"status": r["status"] if r else "idle"})
            if action in ("pause", "stop"):
                r["_pause"] = (action == "pause")
                r["halt"].set()
                if action == "stop":
                    vpn.disconnect()      # STOP tears the tunnel down; pause keeps it
                return self._json(200, {"status": "stopping"})
        return self._json(400, {"error": "unknown action"})

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

    def _report_reason_fn(self, eid):
        store = self._store()
        eng = store.get_engagement(eid) or {}
        cfg = json.loads(eng.get("config") or "{}")
        rc = cfg.get("reasoning") or (store.get_settings() or {}).get("reasoning")
        if not rc:
            return None
        from .reasoning import ReasoningLadder
        ladder = ReasoningLadder(rc)
        def rf(prompt):
            res = ladder.reason(prompt, "report", role="report")
            return res.text if res else None
        return rf

    def _scope_reason_fn(self, eid):
        store = self._store()
        eng = store.get_engagement(eid) or {}
        cfg = json.loads(eng.get("config") or "{}")
        rc = cfg.get("reasoning") or (store.get_settings() or {}).get("reasoning")
        if not rc:
            return None
        from .reasoning import ReasoningLadder
        ladder = ReasoningLadder(rc)
        def rf(prompt):
            res = ladder.reason(prompt, "scope", role="scope")
            return res.text if res else None
        return rf

    def _validate_scope_payload(self, raw_scope):
        """Same validation as engagement creation: derive the flat scope, refuse an
        enabled-but-empty category (would silently mean "the whole domain"), and
        require at least one concrete in-scope target. Shared by `_create_engagement`
        and `/api/scope/apply` so the scope agent can never write a weaker-checked
        scope than a fresh engagement would accept."""
        scope = _derive_scope(raw_scope or {})
        empty = _enabled_without_target(raw_scope or {})
        if empty:
            return None, (f"selected scope {'categories' if len(empty) > 1 else 'category'} "
                          f"{', '.join(empty)} need a target — supply an in-scope host/IP/CIDR "
                          f"(or deselect it); a blank category is not scanned as the full domain")
        if not (scope.get("in_scope_domains") or scope.get("in_scope_cidrs")):
            return None, "scope must define at least one in-scope domain or CIDR (target required)"
        return scope, None

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
        if path == "/api/settings/export" and method == "GET":
            # everything persisted (providers, keys, ladder, user info). The sudo and
            # attack-box passwords live only in memory, so they are never in here.
            blob = json.dumps(self._store().get_settings(), indent=2).encode()
            return (200, "application/json; charset=utf-8", blob,
                    {"Content-Disposition": 'attachment; filename="atptmaster-settings.json"'})
        if path == "/api/settings/import" and method == "POST":
            s = data.get("settings")
            if not isinstance(s, dict):
                return self._json(400, {"error": "settings must be a JSON object"})
            s.pop("sudo_password", None)              # never accept a sudo password from a file
            self._store().set_settings(s)
            return self._json(200, _redact_settings(self._store().get_settings()))
        if path == "/api/settings/sudo-password":
            if method != "POST":
                return self._json(405, {"error": "POST only; this value is never read back"})
            privilege.set_password(data.get("password") or "")
            return self._json(200, {"ok": True, "has_password": privilege.has_password()})
        if path == "/api/providers/status" and method == "GET":
            return self._json(200, {"providers": [
                {"name": n, **providers.status(n)} for n in providers.known()]})
        if path == "/api/models" and method == "GET":
            return self._list_models(query)
        if path == "/api/update/check" and method == "GET":
            return self._json(200, selfupdate.check(self.project_dir))
        if path == "/api/update/apply" and method == "POST":
            return self._json(200, selfupdate.apply(self.project_dir))
        if path == "/api/vpn/status" and method == "GET":
            return self._json(200, vpn.status())
        if path == "/api/vpn/disconnect" and method == "POST":
            return self._json(200, vpn.disconnect())
        if path == "/api/providers/install" and method == "POST":
            return self._provider_install(data)
        if path == "/api/providers/login" and method == "POST":
            return self._provider_login(data)
        if path == "/api/toolbox":
            with Toolbox(self.project_dir / "toolbox") as tb:
                if method == "GET":
                    return self._json(200, {"skills": tb.list_skills()})
                if method == "DELETE":
                    return self._json(200, {"deleted": tb.delete(query.get("name") or "")})
                return self._json(405, {"error": "GET or DELETE"})

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
            md = self._report_builder()(store, eid, self.project_dir,
                                        reason_fn=self._report_reason_fn(eid))
            return (200, "text/markdown; charset=utf-8", md.encode(),
                    {"Content-Disposition": f'attachment; filename="{eid}-ptes-report.md"'})
        if path == "/api/settings/ctf":
            if method == "GET":
                return self._json(200, self._get_ctf(store, eid))
            if method == "POST":
                return self._save_ctf(store, eid, data)
        if path == "/api/upload" and method == "POST":
            return self._upload(eid, data)
        if path == "/api/vpn/connect" and method == "POST":
            return self._vpn_connect(store, eid, data)
        if path == "/api/run/start" and method == "POST":
            eng = store.get_engagement(eid)
            # Startup scope confirmation (offensive agent): before ANY action, in
            # every mode, the operator confirms the exact in-scope targets. Catches
            # typos. Runs before the VPN gate so nothing connects until confirmed.
            if offensive_agent_on(eng):
                payload = _scope_confirm_payload(json.loads(eng.get("scope") or "{}"))
                if data.get("scope_confirm") != payload["hash"]:
                    return self._json(200, {"needs_scope_confirm": True, **payload,
                        "message": "Confirm the exact in-scope targets before the agent runs."})
            cfg = json.loads(eng.get("config") or "{}")
            vpath = (cfg.get("ctf") or {}).get("vpn_config_path")
            if vpath and not vpn.is_up():
                # RUN brings the tunnel up itself; needs the sudo password once.
                pw = data.get("sudo_password")
                if pw:
                    privilege.set_password(pw)
                if not privilege.current_password():
                    return self._json(200, {"needs_sudo": True, "for": "run",
                        "message": "sudo password required to bring up the VPN before the run"})
            else:
                vpath = None      # already up or none configured -> nothing to connect
            return self._start_run(eid, data.get("mode") or eng["mode"], vpn_path=vpath)
        if path == "/api/run/control" and method == "POST":
            return self._control_run(eid, data.get("action"))
        if path == "/api/run/status" and method == "GET":
            return self._json(200, self._run_status(eid))
        if path == "/api/scope" and method == "GET":
            eng = store.get_engagement(eid)
            return self._json(200, {"scope": json.loads(eng.get("scope") or "{}"),
                                    "name": eng.get("name"), "mode": eng.get("mode")})
        if path == "/api/report-settings":
            if method == "GET":
                cfg = json.loads(store.get_engagement(eid).get("config") or "{}")
                return self._json(200, (cfg.get("report") or {}))
            if method == "POST":
                findings = data.get("findings")
                if not isinstance(findings, dict):
                    return self._json(400, {"error": "findings must be an object"})
                store.update_engagement_config(eid, {"report": {"findings": findings}})
                return self._json(200, {"ok": True})
        if path == "/api/mode" and method == "POST":
            mode = data.get("mode")
            if mode not in ("step", "semi", "full"):
                return self._json(400, {"error": "mode must be step/semi/full"})
            store.set_mode(eid, mode)
            store.add_event(eid, None, None, "info", "mode_set", f"mode set to {mode} via UI", None)
            return self._json(200, {"ok": True, "mode": mode})
        if path == "/api/scope/chat" and method == "POST":
            from modules.agent_scope.agent import build_prompt, extract_proposed_scope
            rf = self._scope_reason_fn(eid)
            reply = ""
            if rf:
                try:
                    reply = rf(build_prompt(data.get("typed_scope"), data.get("messages") or [])) or ""
                except Exception:
                    reply = ""
            return self._json(200, {"reply": reply, "proposed_scope": extract_proposed_scope(reply)})
        if path == "/api/scope/apply" and method == "POST":
            # SAFETY: same validation as engagement creation (never a weaker check);
            # this only writes the engagement's scope — the deterministic startup
            # scope-confirmation gate in /api/run/start still runs before any scanning.
            scope, err = self._validate_scope_payload(data.get("scope") or {})
            if err:
                return self._json(400, {"error": err})
            store.set_scope(eid, scope)
            store.add_event(eid, "scope", None, "info", "scope_set",
                            "scope written via scope agent (pending startup confirmation)", None)
            return self._json(200, {"scope": scope})

        return self._json(404, {"error": "no such route"})

    def _create_engagement(self, data):
        eid = (data.get("engagement") or "").strip()
        if not valid_eid(eid):
            return self._json(400, {"error": "engagement id must be 1-64 chars of [A-Za-z0-9_-]"})
        raw_scope = data.get("scope") or {}
        scope, err = self._validate_scope_payload(raw_scope)
        if err:
            return self._json(400, {"error": err})
        store = self._store()
        engine = (data.get("engine") or "director")
        existing = store.get_engagement(eid)
        config = json.loads(existing["config"]) if existing and existing.get("config") else {}
        config["offensive_agent"] = {"enabled": engine != "classic"}
        store.create_engagement(eid, data.get("name") or eid, scope, f"{eid}.scope.json",
                                data.get("mode") or "semi", config)
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

    def _list_models(self, query):
        """Live model list for one configured provider. Reads the raw provider
        config server-side (including any stored key) to make the request; the key
        is never returned. `provider` is the reasoning-provider name."""
        name = (query.get("provider") or "").strip()
        provs = (self._store().get_settings().get("reasoning") or {}).get("providers", {})
        cfg = provs.get(name)
        if not cfg:
            return self._json(400, {"error": f"no configured provider '{name}'"})
        model_ids, err = models.list_models(cfg)
        return self._json(200, {"provider": name, "models": model_ids, "error": err})

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

    def _upload(self, eid, data):
        """Save a file the operator picked in the browser (its bytes, base64) under
        var/uploads/<eid>/ and return the server-side path to use. The browser can't
        expose the real local path, so we persist a copy and reference that."""
        name = os.path.basename((data.get("name") or "").strip())
        content = data.get("content_b64") or ""
        if not name or not content:
            return self._json(400, {"error": "name and content_b64 required"})
        try:
            raw = base64.b64decode(content.split(",")[-1])         # strip data: prefix if present
        except Exception:
            return self._json(400, {"error": "invalid base64 content"})
        if len(raw) > 25 * 1024 * 1024:
            return self._json(400, {"error": "file too large (max 25 MB)"})
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "file"
        dest_dir = self.project_dir / "var" / "uploads" / eid
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / safe
        dest.write_bytes(raw)
        return self._json(200, {"path": str(dest.resolve()), "name": safe, "size": len(raw)})

    def _vpn_connect(self, store, eid, data):
        """Bring up the engagement's stored .ovpn in the background. openvpn needs
        root, so it uses the sudo password (memory-only); asks for it if unset."""
        cfg = json.loads(store.get_engagement(eid).get("config") or "{}")
        path = (cfg.get("ctf") or {}).get("vpn_config_path") or data.get("config")
        if not path:
            return self._json(400, {"error": "no VPN config set for this engagement (Scope → CTF)"})
        pw = data.get("sudo_password")
        if pw:
            privilege.set_password(pw)
        if not privilege.current_password() and not vpn.is_up():
            return self._json(200, {"needs_sudo": True, "message": "sudo password required to start the VPN"})
        res = vpn.connect(path, privilege.current_password())
        store.add_event(eid, None, None, "info", "vpn_connect",
                        f"VPN connect requested ({path}): {res.get('status') or res.get('error')}", None)
        return self._json(200, res)

    def _get_ctf(self, store, eid) -> dict:
        cfg = json.loads(store.get_engagement(eid).get("config") or "{}")
        ctf = dict(cfg.get("ctf") or {})
        ctf["attackbox_has_password"] = privilege.has_attackbox_password(eid)
        ctf["offensive_agent"] = cfg.get("offensive_agent") or {}
        ctf["osint"] = cfg.get("osint") or {}
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
        if "offensive_agent" in data:
            # Stored at config top-level (not under ctf) — this is what
            # offensive_agent_on() and the engine read.
            oa = data.get("offensive_agent") or {}
            agent = {"enabled": bool(oa.get("enabled"))}
            if oa.get("max_steps"):
                agent["max_steps"] = int(oa["max_steps"])
            bins = [str(b).strip() for b in (oa.get("allow_bins") or []) if str(b).strip()]
            if bins:
                agent["allow_bins"] = bins
            store.update_engagement_config(eid, {"offensive_agent": agent})
        if "osint_context" in data:
            store.update_engagement_config(eid, {"osint": {"context": str(data.get("osint_context") or "")}})
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


def make_server(project_dir, port=8787, host="127.0.0.1"):
    """Build the console's ThreadingHTTPServer without starting it.

    Returns the httpd; the caller runs it (serve_forever, or in a thread for the
    desktop app). Shared by `serve` (blocking CLI) and `atpt/desktop.py`.
    """
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

        def do_DELETE(self):
            self._do("DELETE")

        def log_message(self, *a):
            pass

    return ThreadingHTTPServer((host, port), Handler)


def serve(project_dir, port=8787, host="127.0.0.1"):
    httpd = make_server(project_dir, port=port, host=host)
    print(f"ATPTmaster console: http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    finally:
        vpn.disconnect()          # tear any lab/CTF tunnel down when the console stops


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
.msg.user{align-self:flex-end;background:#1f6feb33;border:1px solid #1f6feb55}
.msg.assistant{align-self:flex-start;background:var(--field);border:1px solid var(--edge)}
.chat{display:flex;flex-direction:column;gap:8px}
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
.sheet{background:var(--panel);border:1px solid var(--edge);border-radius:12px;width:100%;max-width:880px;display:flex;flex-direction:column;max-height:90vh;overflow:hidden}
.sheettop,.sheetbot{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--edge)}
.sheetbot{border-bottom:0;border-top:1px solid var(--edge);justify-content:flex-end}
.sheettop b{font-size:15px}.sheettop .sp{flex:1}
.sheetbody{display:flex;min-height:0;flex:1;overflow:hidden}
.navcol{width:196px;flex:none;border-right:1px solid var(--edge);overflow:auto;padding:8px;display:flex;flex-direction:column;gap:2px}
.navgrp{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);padding:10px 8px 2px}
.nav{background:transparent;border:1px solid transparent;color:var(--fg);text-align:left;padding:7px 10px;border-radius:6px}
.nav:hover{background:var(--field)}
.nav.on{background:var(--acc);border-color:var(--acc);color:#fff}
.headlogo{height:52px;width:auto;display:block}
.hicon{font-size:18px;line-height:1;padding:4px 10px}
.panels{padding:16px;overflow:auto;flex:1}
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
  <button class="ghost hicon" id="menubtn" title="Menu">☰</button>
  <b>ATPTmaster</b>
  <select id="engsel" title="engagement"></select>
  <span class="sp"></span>
  <button id="runbtn">▶ Run</button>
  <button class="ghost hidden" id="pausebtn">⏸ Pause</button>
  <button class="ghost hidden" id="stopbtn">⏹ Stop</button>
  <img class="headlogo" src="/assets/logo.png" alt="ATPTmaster" title="ATPTmaster">
</header>

<div class="wrap">
  <div class="col">
    <div class="card">
      <h3>Chat control</h3>
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
      <div class="row" style="margin-top:10px">
        <button class="ghost" id="menuScope">Define scope &amp; target</button>
        <button class="ghost" id="demobtn">Load demo</button>
        <span class="muted" id="createmsg"></span>
      </div>
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
    <div class="sheettop"><b>☰ ATPTmaster settings</b><span class="sp"></span>
      <button class="ghost" id="setclose">✕</button></div>
    <div class="sheetbody">
      <nav class="navcol">
        <div class="navgrp">User</div>
        <button class="nav on" data-tab="userinfo">User info</button>
        <div class="navgrp">AI settings</div>
        <button class="nav" data-tab="providers">API providers</button>
        <button class="nav" data-tab="subs">Subscription CLI</button>
        <button class="nav" data-tab="ollama">Local LLM</button>
        <button class="nav" data-tab="models">Models</button>
        <div class="navgrp">Scope</div>
        <button class="nav" data-tab="scope">Target &amp; scope</button>
        <button class="nav" data-tab="ctf">CTF / engagement</button>
        <div class="navgrp">App settings</div>
        <button class="nav" data-tab="appmode">Mode</button>
        <button class="nav" data-tab="appearance">Appearance</button>
        <button class="nav" data-tab="ladder">Model ladder</button>
        <button class="nav" data-tab="report">Report</button>
        <button class="nav" data-tab="backup">Backup</button>
        <button class="nav" data-tab="update">Update</button>
        <button class="nav" data-tab="toolbox">Toolbox</button>
      </nav>
      <div class="panels">
        <div class="panel" data-panel="userinfo">
          <div class="hint">Your details — the <b>name</b> appears on generated reports. Stored locally.</div>
          <div class="grid2">
            <label>Name<input id="ui_name" placeholder="Avi Twil"></label>
            <label>Company<input id="ui_company" placeholder="Acme Security"></label>
            <label>Phone<input id="ui_phone" placeholder="+972 50 000 0000"></label>
            <label>Email<input id="ui_email" placeholder="you@example.com"></label>
          </div>
        </div>
        <div class="panel hidden" data-panel="providers">
          <div class="hint">Hosted API providers. Per provider, <b>paste a key</b> (stored on this machine) or name an <b>env var</b> (read at call time — nothing stored).</div>
          <div id="httpList"></div>
          <button class="ghost" id="addHttp">+ Add API provider</button>
        </div>
        <div class="panel hidden" data-panel="subs">
          <div class="hint">Subscription CLIs you're logged into. Claude, Gemini &amp; Codex are ready by default — <b>Install (auto)</b> installs dependencies + the CLI (asks only for your sudo password). Or add your own with <b>+ Custom CLI</b>.</div>
          <div id="subList"></div>
          <button class="ghost" id="addSub">+ Custom CLI provider</button>
        </div>
        <div class="panel hidden" data-panel="ollama">
          <div class="hint">Local models via <b>Ollama</b>. Nothing leaves your machine.</div>
          <div id="ollamaList"></div>
          <button class="ghost" id="addOllama">+ Add local model</button>
        </div>
        <div class="panel hidden" data-panel="models">
          <div class="hint">Live models for each configured provider (fetched from the provider — needs its key/CLI configured). Save your providers first.</div>
          <div id="modelsList"></div>
        </div>
        <div class="panel hidden" data-panel="scope">
          <div class="hint">Define the target and per-domain scope. Tick the domains in play; for each, list what's in scope and (optionally) what's explicitly out.</div>
          <div class="grid2">
            <label>Engagement id<input id="f_id" placeholder="acme-2026 / thm-box"></label>
            <label>Target name<input id="f_name" placeholder="THM: Infinity Pool"></label>
            <label class="full"><b>Target (IP or CIDR)</b> — the primary in-scope host<input id="f_target" placeholder="10.10.10.10  or  10.10.10.0/24"></label>
            <label>Default mode<select id="f_mode"><option>step</option><option selected>semi</option><option>full</option></select></label>
            <label class="hint">Engine
              <select id="engine">
                <option value="director" selected>Director (LLM drives the engagement)</option>
                <option value="classic">Classic pipeline (fixed scan chain)</option>
              </select>
            </label>
          </div>
          <div class="hint" style="margin-top:6px">Optional — refine with per-domain scope below (Web/API hosts, extra Infra ranges, out-of-scope):</div>
          <div id="scopeDomains" style="margin-top:6px;display:flex;flex-direction:column;gap:8px"></div>
          <div class="row" style="margin-top:10px">
            <button id="createbtn">Create / update engagement</button>
            <span class="hint" id="createmsg"></span>
          </div>
          <div class="hint" style="margin-top:14px">Or describe your scope in plain language — the scope agent will restate it (or ask for what's missing) before anything is written:</div>
          <div id="scope_chat" class="chat" style="max-height:220px;overflow:auto;margin-top:6px"></div>
          <div class="row">
            <input id="scope_msg" placeholder="Describe or confirm your scope…" style="flex:1">
            <button id="scope_send">Send</button>
            <button id="scope_apply" class="ghost">Approve &amp; write scope</button>
          </div>
        </div>
        <div class="panel hidden" data-panel="ctf">
          <div class="hint" id="ctfEng">Applies to the selected engagement.</div>
          <label class="hint full">Goals — what the LLM should look for<textarea id="c_goals" rows="3" placeholder="e.g. find user.txt and root.txt; enumerate web + SSH"></textarea></label>
          <label class="hint full">OSINT context / challenge page — text the passive-recon (OSINT) phase reasons over<textarea id="c_osint" rows="4" placeholder="Paste the THM/HTB challenge page, or any known public info about the target"></textarea></label>
          <div class="toggle full"><input type="checkbox" id="c_agent">
            <label for="c_agent"><b>LLM offensive agent</b> — let the AI drive scan/exploit commands per target
            (scope-enforced in every mode; you confirm targets before it runs)</label></div>
          <div class="row" id="c_agent_opts">
            <label class="hint">Max steps<input id="c_agent_steps" type="number" min="1" value="20" style="width:90px"></label>
            <label class="hint" style="flex:1">Extra allowed tools (comma-sep, opt-in)<input id="c_agent_bins" placeholder="sqlmap, hydra"></label></div>
          <label class="hint full">VPN config (.ovpn)
            <div class="row"><input id="c_vpn" readonly placeholder="none selected" style="flex:1">
              <input type="file" id="c_vpn_file" accept=".ovpn,.conf" hidden>
              <button class="ghost" id="c_vpn_pick">Choose…</button></div>
          </label>
          <div class="row"><button class="ghost" id="vpnConnect">▶ Connect VPN (background)</button>
            <button class="ghost" id="vpnDisconnect">Disconnect</button>
            <span class="hint" id="vpnStatus"></span></div>
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
        <div class="panel hidden" data-panel="appmode">
          <div class="hint">Run mode for the selected engagement.</div>
          <label class="full">Mode<select id="a_mode">
            <option value="step">Step-by-step — you approve each step</option>
            <option value="semi" selected>Semi-auto — approve only exploits &amp; attacks</option>
            <option value="full">Full auto — YOLO</option>
          </select></label>
          <span class="hint" id="a_modemsg"></span>
        </div>
        <div class="panel hidden" data-panel="appearance">
          <label class="full">Theme<select id="a_theme">
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select></label>
          <div class="toggle" style="margin-top:12px"><input type="checkbox" id="s_sudo"> <label for="s_sudo" style="color:var(--fg)">Allow sudo (privileged scans)</label></div>
          <div id="sudoPwWrap" class="full hidden">
            <label class="hint">Sudo password (memory only, never saved to disk, re-asked after restart)
              <input type="password" id="s_sudopw" placeholder="••••••••" autocomplete="off"></label>
            <button class="ghost" id="sudoPwBtn" style="margin-top:6px">Set sudo password</button>
            <span class="hint" id="sudoPwMsg"></span>
          </div>
        </div>
        <div class="panel hidden" data-panel="ladder">
          <div class="hint">Ordered models tried top-to-bottom; fall back on error/refusal. Add a model (from those configured in AI settings) with an effort level.</div>
          <ul class="ladder" id="ladder"></ul>
          <div class="prow" style="grid-template-columns:1fr 1fr auto auto;align-items:end">
            <label>Provider<select id="lm_prov"></select></label>
            <label>Model<select id="lm_model"></select></label>
            <label>Effort<select id="lm_effort"><option value="">effort —</option><option>minimal</option><option>low</option><option>medium</option><option>high</option></select></label>
            <button class="ghost" id="lm_add">+ Add model</button>
          </div>
          <span class="hint" id="lm_hint"></span>
          <div class="prow" style="grid-template-columns:1fr 1fr 1fr;margin-top:6px">
            <label>map policy<select id="pol_map"><option>any</option><option>hosted_ok</option><option>local_only</option></select></label>
            <label>exploit policy<select id="pol_exploit"><option>any</option><option>hosted_ok</option><option>local_only</option></select></label>
            <label>report policy<select id="pol_report"><option>any</option><option>hosted_ok</option><option>local_only</option></select></label>
          </div>
          <div class="hint" style="margin-top:16px">Per-role overrides — leave a role on the global ladder above, or switch it to Custom and give it its own ordered ladder (drawn from the same configured providers).</div>
          <div id="roleLadders"></div>
        </div>
        <div class="panel hidden" data-panel="report">
          <div class="hint">Customize the PTES report: untick findings to exclude, add your own note (mitigation/impact) and screenshot file paths per finding.</div>
          <div id="rp_findings"><span class="hint">Select an engagement to customize its report.</span></div>
          <div class="row" style="margin-top:10px">
            <button id="rp_save">Save report settings</button>
            <button class="ghost" id="rp_dl">⬇ Download PTES report</button>
            <span class="hint" id="rp_msg"></span>
          </div>
        </div>
        <div class="panel hidden" data-panel="backup">
          <div class="hint">Save all settings to a file (providers, <b>API keys</b>, model ladder, user info — everything except the in-memory sudo &amp; attack-box passwords), or load them back from a file.</div>
          <div class="row" style="margin-top:8px">
            <button id="bk_export">⬇ Save settings to file</button>
            <input type="file" id="bk_file" accept=".json,application/json" hidden>
            <button class="ghost" id="bk_import">⬆ Load settings from file…</button>
            <span class="hint" id="bk_msg"></span>
          </div>
          <div class="warn" style="margin-top:6px">The exported file contains your API keys in cleartext — store it safely.</div>
        </div>
        <div class="panel hidden" data-panel="update">
          <div class="hint">Update ATPTmaster from its GitHub repository (fast-forward pull of the current branch).</div>
          <div class="row"><button class="ghost" id="upd_check">Check for updates</button><span class="hint" id="upd_status"></span></div>
          <div id="upd_log" style="margin-top:8px"></div>
          <button id="upd_apply" class="hidden" style="margin-top:8px">⬇ Update now</button>
          <div class="hint" id="upd_result" style="margin-top:6px"></div>
        </div>
        <div class="panel hidden" data-panel="toolbox">
          <div class="hint">Strategy Toolbox — skills the agent distilled from successful runs.
            They only <i>suggest</i> commands; every command is still scope-checked at execution
            time. Files live in <code>toolbox/</code> and are hand-editable.</div>
          <ul class="ladder" id="tbList"></ul>
        </div>
      </div>
    </div>
    <div class="sheetbot"><span class="hint" id="setmsg"></span>
      <button id="setsave">Save settings</button></div>
  </div>
</div>

<div id="findingDetail" class="modal hidden">
  <div class="sheet" style="max-width:640px">
    <div class="sheettop"><b id="fd_title">Finding</b><span class="sp"></span>
      <button class="ghost" id="fd_close">✕</button></div>
    <div class="panels" id="fd_body"></div>
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

let ENGS=[], MODE='semi';
function syncMode(){ MODE=(ENGS.find(e=>e.id===ENG)||{}).mode||'semi'; }
async function refreshEngagements(sel){
  const {engagements}=await api('/api/engagements');
  ENGS=engagements;
  const s=$('#engsel');s.innerHTML='';
  engagements.forEach(e=>{const o=document.createElement('option');o.value=e.id;o.textContent=e.id+' — '+(e.name||'');s.appendChild(o)});
  if(sel){s.value=sel}
  ENG=s.value||null; syncMode();
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
let FINDINGS=[];
async function refreshFindings(){
  const {findings}=await api('/api/findings?eng='+encodeURIComponent(ENG));
  FINDINGS=findings;
  if(!findings.length){$('#findings').innerHTML='<span class=muted>No findings yet — run the pipeline.</span>';return}
  const rows=findings.map(f=>`<tr data-fid="${f.id}" style="cursor:pointer"><td><span class="pill sev-${sevCls(f.severity)}">${esc(f.severity||'info')}</span></td>
    <td>${esc(f.title)}<div class=muted style="font-size:11px">${esc((f.evidence&&f.evidence.asset_value)||f.source_tool||'')}</div></td>
    <td class="st-${stCls(f.status)}">${esc(f.status)}</td><td>${esc(f.owasp||'—')}</td><td>${esc(f.cvss??'—')}</td></tr>`).join('');
  $('#findings').innerHTML=`<table><tr><th>Sev</th><th>Finding</th><th>Status</th><th>OWASP</th><th>CVSS</th></tr>${rows}</table>`;
  document.querySelectorAll('#findings tr[data-fid]').forEach(tr=>tr.onclick=()=>showFindingDetail(+tr.dataset.fid));
}

/* ---- finding detail panel: full write-up + shared screenshot slot ---- */
function fdRow(label,val){ return val?`<div style="margin-top:8px"><div class="hint" style="text-transform:uppercase;letter-spacing:.04em">${esc(label)}</div><div style="white-space:pre-wrap">${esc(val)}</div></div>`:''; }
async function showFindingDetail(id){
  const f=FINDINGS.find(x=>x.id===id); if(!f)return;
  const ev=f.evidence||{};
  const rs=await api('/api/report-settings?eng='+encodeURIComponent(ENG));
  const shots=((rs.findings||{})[id]||{}).screenshots||[];
  $('#fd_title').textContent=f.title||('Finding #'+id);
  $('#fd_body').innerHTML=`
    <div class="row">
      <span class="pill sev-${sevCls(f.severity)}">${esc(f.severity||'info')}</span>
      <span class="st-${stCls(f.status)}">${esc(f.status||'candidate')}</span>
      ${f.owasp?`<span class="badge">${esc(f.owasp)}</span>`:''}
      ${(f.cvss!=null&&f.cvss!=='')?`<span class="badge">CVSS ${esc(f.cvss)}</span>`:''}
    </div>
    ${fdRow('Affected',ev.asset_value)}
    ${fdRow('Description',ev.description)}
    ${fdRow('How it was proven',ev.reproduction)}
    ${fdRow('Impact',ev.impact)}
    ${fdRow('Remediation',ev.remediation)}
    ${fdRow('Confidence',ev.confidence)}
    <div style="margin-top:12px">
      <div class="hint" style="text-transform:uppercase;letter-spacing:.04em">Screenshots</div>
      <div id="fd_shots" class="row" style="flex-wrap:wrap;margin-top:6px">${shots.map(p=>
        `<img src="file://${esc(p)}" title="${esc(p)}" style="max-width:160px;max-height:120px;border:1px solid var(--edge);border-radius:6px">`).join('')
        ||'<span class="hint">none yet</span>'}</div>
      <div class="row" style="margin-top:8px">
        <input type="file" id="fd_shot_file" accept="image/*" hidden>
        <button class="ghost" id="fd_shot_pick">+ Add screenshot</button>
        <span class="hint" id="fd_shot_msg"></span>
      </div>
    </div>`;
  $('#fd_shot_pick').onclick=()=>$('#fd_shot_file').click();
  $('#fd_shot_file').onchange=async e=>{
    const file=e.target.files[0]; if(!file)return;
    $('#fd_shot_msg').textContent='uploading…';
    const up=await uploadPicked(file);
    if(up.error){$('#fd_shot_msg').textContent='⚠ '+esc(up.error);return;}
    // merge into the SAME store slot the report customization panel writes —
    // fetch current settings first so every other finding's entry survives.
    const cur=await api('/api/report-settings?eng='+encodeURIComponent(ENG));
    const findings=Object.assign({},cur.findings||{});
    const entry=findings[id]||{};
    findings[id]=Object.assign({},entry,{screenshots:(entry.screenshots||[]).concat([up.path])});
    await api('/api/report-settings?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({findings})});
    $('#fd_shot_msg').textContent='saved ✓';
    showFindingDetail(id);
  };
  $('#findingDetail').classList.remove('hidden');
}
$('#fd_close')&&($('#fd_close').onclick=()=>$('#findingDetail').classList.add('hidden'));
$('#findingDetail')&&($('#findingDetail').onclick=e=>{if(e.target.id==='findingDetail')$('#findingDetail').classList.add('hidden');});
async function refreshTree(){
  const t=await api('/api/tree?eng='+encodeURIComponent(ENG));
  if(!t.branches||!t.branches.length){$('#tree').innerHTML='<span class=muted>—</span>';return}
  $('#tree').innerHTML=`<div class=muted>🎯 ${esc(t.target)}</div>`+t.branches.map(b=>
    `<div class=branch><div class=dom>▸ ${esc(b.domain)} <span class=muted>(${b.findings.length})</span></div>
     <ul>${b.findings.map(f=>`<li><span class="pill sev-${sevCls(f.severity)}">${esc(f.severity)}</span>
       ${esc(f.title)} <span class="st-${stCls(f.status)} muted">${esc(f.status)}</span></li>`).join('')}</ul></div>`).join('');
}

const SCOPE_DOMAINS=[
  {key:'infra',   label:'Infrastructure', inHint:'in-scope CIDRs / IPs (e.g. 203.0.113.0/24)', outHint:'out-of-scope IPs / CIDRs', out:true},
  {key:'web',     label:'Web',            inHint:'in-scope domains / URLs (e.g. acme.com)',    outHint:'out-of-scope hosts',    out:true},
  {key:'api',     label:'API',            inHint:'in-scope API hosts',                          outHint:'out-of-scope hosts',    out:true},
  {key:'ai',      label:'AI / LLM',       inHint:'in-scope model/chat endpoints',               outHint:'out-of-scope',          out:true},
  {key:'cloud',   label:'Cloud',          inHint:'in-scope accounts / hosts',                   outHint:'out-of-scope',          out:true},
  {key:'mobile',  label:'Mobile',         inHint:'APK path / package name',                     out:false},
  {key:'wireless',label:'Wireless',       inHint:'SSIDs / BSSIDs',                              out:false},
];
let SCOPEDATA={};   // key -> {enabled, in:[], out:[]}
function renderScope(){
  $('#scopeDomains').innerHTML=SCOPE_DOMAINS.map(d=>{
    const s=SCOPEDATA[d.key]||{}; const on=!!s.enabled;
    return `<div class="prow" data-dk="${d.key}" style="grid-template-columns:1fr">
      <div class="toggle"><input type="checkbox" class="d_on" ${on?'checked':''}> <label style="color:var(--fg)"><b>${d.label}</b></label></div>
      <div class="d_body ${on?'':'hidden'}" style="display:flex;flex-direction:column;gap:6px">
        <label class="hint">In scope<textarea class="d_in" rows="2" placeholder="${d.inHint}">${esc((s.in||[]).join(', '))}</textarea></label>
        ${d.out?`<label class="hint">Out of scope<textarea class="d_out" rows="1" placeholder="${d.outHint}">${esc((s.out||[]).join(', '))}</textarea></label>`:''}
      </div></div>`;}).join('');
  $('#scopeDomains').querySelectorAll('.prow').forEach(row=>{
    const cb=row.querySelector('.d_on');
    cb.onchange=()=>row.querySelector('.d_body').classList.toggle('hidden',!cb.checked);
  });
}
function isIpOrCidr(v){ return /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/.test(v) || v.includes(':'); }
function collectScope(){
  const domains={};
  $('#scopeDomains').querySelectorAll('.prow').forEach(row=>{
    const key=row.dataset.dk; const enabled=row.querySelector('.d_on').checked;
    const inv=row.querySelector('.d_in'); const outv=row.querySelector('.d_out');
    domains[key]={enabled, in:split(inv?inv.value:''), out:split(outv?outv.value:'')};
  });
  const scope={domains};
  const target=$('#f_target').value.trim();
  if(target){ if(isIpOrCidr(target)) scope.in_scope_cidrs=[target]; else scope.in_scope_domains=[target]; }
  return scope;
}
async function loadScope(){
  SCOPEDATA={};
  if(ENG){ try{
    const st=await api('/api/scope?eng='+encodeURIComponent(ENG));
    const sc=st.scope||{};
    SCOPEDATA=sc.domains||{};
    $('#f_id').value=ENG; $('#f_name').value=st.name||''; $('#f_mode').value=st.mode||'semi';
    $('#f_target').value=(sc.in_scope_cidrs&&sc.in_scope_cidrs[0])||(sc.in_scope_domains&&sc.in_scope_domains[0])||'';
  }catch(e){} }
  renderScope();
}

/* ---- scope-agent chat: Mode A restates a typed scope, Mode B elicits one ---- */
let SCOPE_MSGS=[], SCOPE_PROPOSED=null;
function scopeFormFilled(){
  if(($('#f_target').value||'').trim()) return true;
  const rows=$('#scopeDomains')?[...$('#scopeDomains').querySelectorAll('.prow')]:[];
  return rows.some(row=>{
    const on=row.querySelector('.d_on'); const inv=row.querySelector('.d_in');
    return on&&on.checked&&inv&&inv.value.trim();
  });
}
function currentTypedScope(){ return scopeFormFilled()?collectScope():null; }
function renderScopeChat(){ $('#scope_chat').innerHTML=SCOPE_MSGS.map(m=>
  `<div class="msg ${esc(m.role)}">${esc(m.text)}</div>`).join(''); $('#scope_chat').scrollTop=1e9; }
async function scopeSend(){
  if(!ENG) return;
  const t=$('#scope_msg').value.trim(); if(t){ SCOPE_MSGS.push({role:'user',text:t}); }
  $('#scope_msg').value=''; renderScopeChat();
  const r=await api('/api/scope/chat?eng='+encodeURIComponent(ENG),{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({typed_scope:currentTypedScope(),messages:SCOPE_MSGS})});
  if(r.reply){ SCOPE_MSGS.push({role:'assistant',text:r.reply}); }
  if(r.proposed_scope){ SCOPE_PROPOSED=r.proposed_scope; }
  renderScopeChat();
}
async function scopeApply(){
  if(!ENG) return;
  const scope=SCOPE_PROPOSED||currentTypedScope();
  if(!scope){ SCOPE_MSGS.push({role:'assistant',text:'No scope to write yet — describe it first.'}); renderScopeChat(); return; }
  const r=await api('/api/scope/apply?eng='+encodeURIComponent(ENG),{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({scope})});
  if(r.error){ SCOPE_MSGS.push({role:'assistant',text:'⚠ '+r.error}); renderScopeChat(); return; }
  SCOPE_PROPOSED=null;
  SCOPE_MSGS.push({role:'assistant',text:'Scope written. It will be confirmed again before scanning starts.'});
  renderScopeChat(); loadScope();
}
$('#scope_send')&&($('#scope_send').onclick=scopeSend);
$('#scope_msg')&&($('#scope_msg').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();scopeSend();}}));
$('#scope_apply')&&($('#scope_apply').onclick=scopeApply);

$('#createbtn').onclick=async()=>{
  const scope=collectScope();
  const r=await api('/api/engagement',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({engagement:$('#f_id').value.trim(),name:$('#f_name').value.trim(),scope,mode:$('#f_mode').value,
      engine:($('#engine')&&$('#engine').value)||'director'})});
  if(r.error){$('#createmsg').textContent='⚠ '+r.error;return}
  $('#createmsg').textContent='saved ✓';chat('sys','Engagement <b>'+esc(r.engagement.id)+'</b> scope saved. Send <b>run</b>.');
  await refreshEngagements(r.engagement.id);
  $('#settings').classList.add('hidden');
};
$('#demobtn').onclick=async()=>{
  const r=await api('/api/demo',{method:'POST'});
  chat('sys','Loaded <b>demo</b> engagement (4 seeded assets). Send <b>run full</b> to map → validate → report.');
  await refreshEngagements(r.engagement.id);
};
function split(v){return (v||'').split(/[,\n]/).map(x=>x.trim()).filter(Boolean)}

async function send(){
  const v=$('#chatin').value.trim(); if(!v||!ENG)return; $('#chatin').value='';
  chat('me',esc(v));
  const r=await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({eng:ENG,message:v})});
  if(r.error){chat('sys','⚠ '+esc(r.error));return}
  chat('sys',r.reply);await refreshAll();
}
$('#sendbtn').onclick=send;$('#chatin').addEventListener('keydown',e=>{if(e.key==='Enter')send()});
let RUNPOLL=null, RUNBUSY=false;
function setRunUI(status){
  const running=(status==='running'||status==='stopping');
  $('#runbtn').classList.toggle('hidden',running);
  $('#pausebtn').classList.toggle('hidden',!running);
  $('#stopbtn').classList.toggle('hidden',!running);
  $('#runbtn').textContent=(status==='paused')?'▶ Resume':'▶ Run';
}
async function pollRun(){
  if(!ENG){setRunUI('idle');return;}
  const s=await api('/api/run/status?eng='+encodeURIComponent(ENG));
  setRunUI(s.status);
  if(s.status==='running'||s.status==='stopping'){ RUNBUSY=true; if(!RUNPOLL)RUNPOLL=setInterval(pollRun,1500); return; }
  if(RUNPOLL){clearInterval(RUNPOLL);RUNPOLL=null;}
  if(RUNBUSY){ RUNBUSY=false;
    if(s.last)chat('sys','Run <b>'+esc(s.status)+'</b>: executed '+JSON.stringify(s.last.executed||[])+
      (s.last.gated_on?' · ⏸ before <b>'+esc(s.last.gated_on)+'</b> (approve to continue)':'')+
      (s.last.halted?' · ⏹ halted between steps':''));
    await refreshAll();
  }
}
$('#runbtn').onclick=async()=>{
  if(!ENG){chat('sys','Create or select an engagement first (☰ menu → Scope).');return}
  const url='/api/run/start';const hdr={'Content-Type':'application/json'};
  const body={eng:ENG,mode:MODE};
  const post=()=>api(url,{method:'POST',headers:hdr,body:JSON.stringify(body)});
  let r=await post();
  if(r&&r.needs_scope_confirm){
    const ok=confirm('The agent will operate ONLY against:\n\n'+(r.targets||[]).join('\n')+'\n\nProceed?');
    if(!ok){chat('sys','Run cancelled — scope not confirmed.');return;}
    body.scope_confirm=r.hash; r=await post(); }
  if(r&&r.needs_sudo){ const pw=prompt('sudo password (to bring up the VPN for this run):');
    if(!pw){chat('sys','Run cancelled — VPN needs a sudo password to start.');return;}
    body.sudo_password=pw; r=await post(); }
  if(r&&r.error){chat('sys','⚠ '+esc(r.error));return;}
  chat('sys','▶ Run started (<b>'+MODE+'</b>)…'); setRunUI('running'); RUNBUSY=true; pollRun();
};
function runControl(action,msg){ if(!ENG)return; chat('sys',msg);
  api('/api/run/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({eng:ENG,action})}); }
$('#pausebtn').onclick=()=>runControl('pause','⏸ pausing after the current step…');
$('#stopbtn').onclick=()=>runControl('stop','⏹ stopping after the current step & disconnecting VPN…');
function downloadReport(){ if(!ENG){chat('sys','No engagement selected.');return} window.location='/api/report?eng='+encodeURIComponent(ENG); }
$('#engsel').onchange=async()=>{ENG=$('#engsel').value;syncMode();await refreshAll();pollRun();};

/* ===== Settings ===== */
let SET={}, HTTP=[], SUB=[], OLLAMA=[], PREF=[], PSTATUS={}, MODELS={}, LADDER=[];
let ROLE_LADDERS={}, ROLE_CUSTOM={};
const ROLE_ORDER=['director','osint','active_recon','skill','scope','map','exploit','report'];
const ROLE_LABELS={director:'Director',osint:'OSINT / passive recon',active_recon:'Active recon',
  skill:'Skill distiller',scope:'Scope agent',map:'Map/PTT enricher',exploit:'Exploit proposer',
  report:'Report author/manager'};
function applyTheme(mode){ // 'system' | 'light' | 'dark'
  const el=document.documentElement;
  if(mode==='light'||mode==='dark') el.setAttribute('data-theme',mode);
  else el.removeAttribute('data-theme');   // system → follow prefers-color-scheme
}
function themePref(){try{return localStorage.getItem('atpt_theme')||'system';}catch(e){return 'system';}}
applyTheme(themePref());

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
  // Model-based ladder: use it if present, else migrate from the provider preference.
  LADDER=(r.ladder||[]).map(e=>({provider:e.provider,model:e.model||'',effort:e.effort||''}));
  if(!LADDER.length && PREF.length) LADDER=PREF.map(n=>({provider:n,model:(provs[n]||{}).model||'',effort:''}));
  const pol=r.policy||{};
  $('#pol_map').value=pol.map||'any';$('#pol_exploit').value=pol.exploit||'any';$('#pol_report').value=pol.report||'any';
  decomposeRoles();
}
function allNames(){return [...HTTP,...SUB,...OLLAMA].map(p=>p.name).filter(Boolean);}
function reconcileLadder(){const names=allNames();LADDER=LADDER.filter(e=>names.includes(e.provider));}

/* ---- per-role model ladders (role left unset falls back to the global ladder) ---- */
function decomposeRoles(){
  const roles=(SET.reasoning||{}).roles||{};
  ROLE_LADDERS={};ROLE_CUSTOM={};
  ROLE_ORDER.forEach(role=>{
    const rl=(roles[role]||{}).ladder;
    if(Array.isArray(rl)&&rl.length){
      ROLE_LADDERS[role]=rl.map(e=>({provider:e.provider,model:e.model||'',effort:e.effort||''}));
      ROLE_CUSTOM[role]=true;
    } else {
      ROLE_LADDERS[role]=[];
      ROLE_CUSTOM[role]=false;
    }
  });
}
function reconcileRoleLadders(){const names=allNames();
  ROLE_ORDER.forEach(role=>{ROLE_LADDERS[role]=(ROLE_LADDERS[role]||[]).filter(e=>names.includes(e.provider));});
}
function roleLadderRow(role,i){
  const list=ROLE_LADDERS[role]||[]; const e=list[i];
  return `<li><span class="nm">${i+1}. <b>${esc(e.provider)}</b>${e.model?' · '+esc(e.model):''}${e.effort?' <span class="badge">'+esc(e.effort)+'</span>':''}</span>
    <button class="ghost rl_up" data-role="${esc(role)}" data-i="${i}" ${i===0?'disabled':''}>↑</button>
    <button class="ghost rl_down" data-role="${esc(role)}" data-i="${i}" ${i===list.length-1?'disabled':''}>↓</button>
    <button class="ghost rl_del" data-role="${esc(role)}" data-i="${i}">✕</button></li>`;
}
function fillRoleModelOptions(role){
  const provSel=document.querySelector(`.rl_prov[data-role="${role}"]`);
  const modelSel=document.querySelector(`.rl_model[data-role="${role}"]`);
  if(!provSel||!modelSel)return;
  const prov=provSel.value;
  let list=MODELS[prov]; if(!list){ const st=PSTATUS[prov]; if(st&&st.models&&st.models.length)list=st.models; }
  if(!list){ modelSel.innerHTML='<option value="">— fetch in Models tab —</option>'; return; }
  modelSel.innerHTML='<option value="">(default)</option>'+list.map(m=>`<option value="${esc(m)}">${esc(m)}</option>`).join('');
}
function renderRoleLadders(){
  reconcileRoleLadders();
  const box=$('#roleLadders'); if(!box)return;
  const names=allNames();
  const provOpts=names.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('')||'<option value="">(configure a provider first)</option>';
  box.innerHTML=ROLE_ORDER.map(role=>{
    const custom=!!ROLE_CUSTOM[role]; const list=ROLE_LADDERS[role]||[];
    return `<div class="prow" data-role="${esc(role)}" style="grid-template-columns:1fr;border-top:1px solid var(--edge);padding-top:10px;margin-top:10px">
      <div class="toggle"><input type="checkbox" class="rl_toggle" data-role="${esc(role)}" ${custom?'':'checked'}>
        <label style="color:var(--fg)"><b>${esc(ROLE_LABELS[role]||role)}</b> — ${custom?'<span class="badge">Custom</span>':'Use global ladder'}</label></div>
      <div class="rl_body ${custom?'':'hidden'}" data-role="${esc(role)}">
        <ul class="ladder">${list.map((e,i)=>roleLadderRow(role,i)).join('')||'<div class=hint>No models yet — add one below.</div>'}</ul>
        <div class="prow" style="grid-template-columns:1fr 1fr auto auto;align-items:end">
          <label>Provider<select class="rl_prov" data-role="${esc(role)}">${provOpts}</select></label>
          <label>Model<select class="rl_model" data-role="${esc(role)}"><option value="">(default)</option></select></label>
          <label>Effort<select class="rl_effort" data-role="${esc(role)}"><option value="">effort —</option><option>minimal</option><option>low</option><option>medium</option><option>high</option></select></label>
          <button class="ghost rl_add" data-role="${esc(role)}">+ Add model</button>
        </div>
      </div>
    </div>`;
  }).join('');
  wireRoleLadders();
  ROLE_ORDER.forEach(role=>{ if(ROLE_CUSTOM[role]) fillRoleModelOptions(role); });
}
function wireRoleLadders(){
  const box=$('#roleLadders'); if(!box)return;
  box.querySelectorAll('.rl_toggle').forEach(cb=>cb.onchange=()=>{
    const role=cb.dataset.role, custom=!cb.checked;
    ROLE_CUSTOM[role]=custom;
    if(!custom) ROLE_LADDERS[role]=[];   // reverting to global drops any custom entries
    renderRoleLadders();
  });
  box.querySelectorAll('.rl_prov').forEach(s=>s.onchange=()=>fillRoleModelOptions(s.dataset.role));
  box.querySelectorAll('.rl_up').forEach(b=>b.onclick=()=>{
    const role=b.dataset.role,i=+b.dataset.i,list=ROLE_LADDERS[role];
    [list[i],list[i-1]]=[list[i-1],list[i]]; renderRoleLadders();});
  box.querySelectorAll('.rl_down').forEach(b=>b.onclick=()=>{
    const role=b.dataset.role,i=+b.dataset.i,list=ROLE_LADDERS[role];
    [list[i],list[i+1]]=[list[i+1],list[i]]; renderRoleLadders();});
  box.querySelectorAll('.rl_del').forEach(b=>b.onclick=()=>{
    const role=b.dataset.role,i=+b.dataset.i;
    ROLE_LADDERS[role].splice(i,1); renderRoleLadders();});
  box.querySelectorAll('.rl_add').forEach(b=>b.onclick=()=>{
    const role=b.dataset.role;
    const prov=document.querySelector(`.rl_prov[data-role="${role}"]`).value;
    if(!prov)return;
    const model=document.querySelector(`.rl_model[data-role="${role}"]`).value||'';
    const effort=document.querySelector(`.rl_effort[data-role="${role}"]`).value||'';
    (ROLE_LADDERS[role]=ROLE_LADDERS[role]||[]).push({provider:prov,model,effort});
    renderRoleLadders();
  });
}

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
  reconcileLadder();
  $('#ladder').innerHTML=LADDER.map((e,i)=>`<li><span class="nm">${i+1}. <b>${esc(e.provider)}</b>${e.model?' · '+esc(e.model):''}${e.effort?' <span class="badge">'+esc(e.effort)+'</span>':''}</span>
    <button class="ghost l_up" data-i="${i}" ${i===0?'disabled':''}>↑</button>
    <button class="ghost l_down" data-i="${i}" ${i===LADDER.length-1?'disabled':''}>↓</button>
    <button class="ghost l_del" data-i="${i}">✕</button></li>`).join('')||'<div class=hint>No models in the ladder yet — add one below.</div>';
  const mv=(i,j)=>{[LADDER[i],LADDER[j]]=[LADDER[j],LADDER[i]];renderLadder();};
  $('#ladder').querySelectorAll('.l_up').forEach(b=>b.onclick=()=>mv(+b.dataset.i,+b.dataset.i-1));
  $('#ladder').querySelectorAll('.l_down').forEach(b=>b.onclick=()=>mv(+b.dataset.i,+b.dataset.i+1));
  $('#ladder').querySelectorAll('.l_del').forEach(b=>b.onclick=()=>{LADDER.splice(+b.dataset.i,1);renderLadder();});
  // populate the provider picker from configured providers
  const names=allNames();
  $('#lm_prov').innerHTML=names.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('')||'<option value="">(configure a provider first)</option>';
  fillModelOptions();
}
function fillModelOptions(){
  const prov=$('#lm_prov').value;
  let list=MODELS[prov]; if(!list){ const st=PSTATUS[prov]; if(st&&st.models&&st.models.length)list=st.models; }
  if(!list){ $('#lm_model').innerHTML='<option value="">— fetch in Models tab —</option>'; return; }
  $('#lm_model').innerHTML='<option value="">(default)</option>'+list.map(m=>`<option value="${esc(m)}">${esc(m)}</option>`).join('');
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
async function loadStatuses(){const r=await api('/api/providers/status');PSTATUS={};(r.providers||[]).forEach(p=>{PSTATUS[p.name]=p; if(p.models&&p.models.length&&!MODELS[p.name])MODELS[p.name]=p.models;});}

/* ---- live model lists ---- */
async function fetchModels(prov,btn){
  if(btn){btn.disabled=true;btn.textContent='fetching…';}
  const r=await api('/api/models?provider='+encodeURIComponent(prov));
  if(btn){btn.disabled=false;btn.textContent='Fetch models';}
  if(r.error && (!r.models||!r.models.length)){ MODELS[prov]=MODELS[prov]||[]; return {error:r.error}; }
  MODELS[prov]=r.models||[]; return {models:MODELS[prov]};
}
function renderModels(){
  const list=[...HTTP.map(p=>({name:p.name,kind:'API · '+p.api})),
    ...SUB.filter(p=>!p.custom&&PSTATUS[p.name]).map(p=>({name:p.name,kind:'Subscription CLI'})),
    ...OLLAMA.map(p=>({name:p.name,kind:'Ollama'}))].filter(p=>p.name);
  if(!list.length){$('#modelsList').innerHTML='<div class=hint>Configure a provider first (AI settings → providers), then Save.</div>';return;}
  $('#modelsList').innerHTML=list.map(p=>`<div class="prow" data-prov="${esc(p.name)}" style="grid-template-columns:1fr auto">
    <div><b>${esc(p.name)}</b> <span class=hint>${esc(p.kind)}</span></div>
    <button class="ghost m_fetch">Fetch models</button>
    <div class="full m_out">${MODELS[p.name]?renderModelList(MODELS[p.name]):'<span class=hint>not fetched yet</span>'}</div>
  </div>`).join('');
  $('#modelsList').querySelectorAll('.m_fetch').forEach(b=>b.onclick=async()=>{
    const row=b.closest('.prow'); const prov=row.dataset.prov; const out=row.querySelector('.m_out');
    out.innerHTML='<span class=hint>fetching…</span>';
    const r=await fetchModels(prov,b);
    out.innerHTML=r.error?('<span class=warn>⚠ '+esc(r.error)+'</span>'):renderModelList(r.models);
  });
}
function renderModelList(models){
  if(!models||!models.length)return '<span class=hint>(none returned)</span>';
  return '<div class=hint>'+models.length+' models</div>'+models.map(m=>`<span class="badge" style="margin:2px 4px 0 0">${esc(m)}</span>`).join('');
}

function showTab(t){document.querySelectorAll('.nav').forEach(x=>x.classList.toggle('on',x.dataset.tab===t));
  document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('hidden',x.dataset.panel!==t));
  if(t==='ladder'){renderLadder();renderRoleLadders();} if(t==='models')renderModels(); if(t==='scope')loadScope(); if(t==='report')loadReport(); if(t==='update')checkUpdate();}
async function loadReport(){
  const box=$('#rp_findings');
  if(!ENG){box.innerHTML='<span class=hint>Select an engagement first.</span>';return;}
  const [f,rs]=await Promise.all([api('/api/findings?eng='+encodeURIComponent(ENG)),api('/api/report-settings?eng='+encodeURIComponent(ENG))]);
  const findings=(f.findings||[]).filter(x=>x.status!=='false_positive'); const cfg=rs.findings||{};
  if(!findings.length){box.innerHTML='<span class=hint>No findings yet — run the pipeline.</span>';return;}
  box.innerHTML=findings.map(x=>{const c=cfg[x.id]||{}; const inc=c.include!==false;
    return `<div class="prow" data-fid="${x.id}" style="grid-template-columns:1fr">
      <div class="toggle"><input type="checkbox" class="r_inc" ${inc?'checked':''}> <label style="color:var(--fg)"><span class="pill sev-${sevCls(x.severity)}">${esc(x.severity||'info')}</span> <b>${esc(x.title)}</b></label></div>
      <label class="hint">Operator note (mitigation / impact)<textarea class="r_note" rows="2">${esc(c.note||'')}</textarea></label>
      <label class="hint">Screenshots<textarea class="r_shots" rows="1" placeholder="pick a file, or paste paths">${esc((c.screenshots||[]).join(', '))}</textarea></label>
      <div class="row"><input type="file" class="r_shot_file" accept="image/*" hidden><button class="ghost r_shot_pick">+ Add screenshot</button></div>
    </div>`;}).join('');
  box.querySelectorAll('.r_shot_pick').forEach(b=>b.onclick=()=>b.closest('.prow').querySelector('.r_shot_file').click());
  box.querySelectorAll('.r_shot_file').forEach(inp=>inp.onchange=async e=>{const f=e.target.files[0]; if(!f)return;
    const ta=inp.closest('.prow').querySelector('.r_shots'); const r=await uploadPicked(f);
    if(r.error){$('#rp_msg').textContent='⚠ '+esc(r.error);return;}
    ta.value=(ta.value.trim()?ta.value.trim()+', ':'')+r.path;});
}
async function saveReport(){
  if(!ENG){$('#rp_msg').textContent='select an engagement';return;} const findings={};
  $('#rp_findings').querySelectorAll('.prow').forEach(row=>{ findings[row.dataset.fid]={
    include:row.querySelector('.r_inc').checked, note:row.querySelector('.r_note').value.trim(),
    screenshots:split(row.querySelector('.r_shots').value)};});
  await api('/api/report-settings?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({findings})});
  $('#rp_msg').textContent='Saved ✓';setTimeout(()=>$('#rp_msg').textContent='',1500);
}
$('#rp_save')&&($('#rp_save').onclick=saveReport);

/* ---- settings backup: export / import ---- */
$('#bk_export')&&($('#bk_export').onclick=()=>{ window.location='/api/settings/export'; });
$('#bk_import')&&($('#bk_import').onclick=()=>$('#bk_file').click());
$('#bk_file')&&($('#bk_file').onchange=async e=>{ const f=e.target.files[0]; if(!f)return;
  let obj; try{ obj=JSON.parse(await f.text()); }catch(err){ $('#bk_msg').textContent='⚠ not valid JSON'; return; }
  const r=await api('/api/settings/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({settings:obj})});
  if(r.error){ $('#bk_msg').textContent='⚠ '+esc(r.error); return; }
  SET=r; await loadStatuses(); decompose(); renderProviders(); renderLadder(); renderRoleLadders();
  $('#ui_name').value=(SET.user_info||{}).name||''; $('#ui_company').value=(SET.user_info||{}).company||'';
  $('#ui_phone').value=(SET.user_info||{}).phone||''; $('#ui_email').value=(SET.user_info||{}).email||'';
  $('#bk_msg').textContent='Loaded ✓'; setTimeout(()=>$('#bk_msg').textContent='',2000);
  e.target.value='';});

/* ---- self update ---- */
async function checkUpdate(){
  $('#upd_status').textContent='checking…'; $('#upd_result').textContent='';
  const r=await api('/api/update/check');
  if(r.repo===false||r.error){ $('#upd_status').textContent='⚠ '+esc(r.error||'not a git checkout'); $('#upd_log').innerHTML=''; $('#upd_apply').classList.add('hidden'); return; }
  if(r.update_available){
    $('#upd_status').innerHTML='<b>update available</b> &nbsp;<span class=hint>'+esc(r.current||'(unversioned)')+' → '+esc(r.latest)+'</span>';
    $('#upd_log').innerHTML='<div class=hint>What\'s new in '+esc(r.latest)+' (latest stable release):</div><pre class=out>'+(r.changelog||[]).map(esc).join('\n')+'</pre>';
    $('#upd_apply').classList.remove('hidden');
  } else {
    $('#upd_status').innerHTML='✓ up to date <span class=hint>('+esc(r.current||r.latest||'—')+')</span>'+(r.note?' <span class=hint>— '+esc(r.note)+'</span>':'');
    $('#upd_log').innerHTML=''; $('#upd_apply').classList.add('hidden');
  }
}
$('#upd_check')&&($('#upd_check').onclick=checkUpdate);
$('#upd_apply')&&($('#upd_apply').onclick=async()=>{
  $('#upd_result').textContent='updating…';
  const r=await api('/api/update/apply',{method:'POST'});
  if(r.ok){ $('#upd_result').innerHTML='✓ updated to <b>'+esc(r.tag||'latest')+'</b> — <b>restart the console</b> to apply (Ctrl-C, then <code>python3 -m atpt serve</code>).<pre class=out>'+esc(r.output||'')+'</pre>'; checkUpdate(); }
  else { $('#upd_result').innerHTML='⚠ '+esc(r.output||r.error||'update failed')+'<pre class=out>'+esc(r.output||'')+'</pre>'; }
});
document.querySelectorAll('.nav').forEach(b=>b.onclick=()=>{if(['providers','subs','ollama','ladder','models'].includes(b.dataset.tab))syncFromDom();showTab(b.dataset.tab);});
$('#lm_prov')&&($('#lm_prov').onchange=fillModelOptions);
$('#lm_add')&&($('#lm_add').onclick=()=>{
  const prov=$('#lm_prov').value; if(!prov){$('#lm_hint').textContent='configure a provider first';return;}
  LADDER.push({provider:prov,model:$('#lm_model').value||'',effort:$('#lm_effort').value||''});
  $('#lm_hint').textContent=''; renderLadder();
});

async function openSettings(tab){
  SET=await api('/api/settings');
  await loadStatuses();                 // need known-CLI list before decomposing
  decompose();
  const ui=SET.user_info||{};
  $('#ui_name').value=ui.name||SET.pentester_name||'';
  $('#ui_company').value=ui.company||'';$('#ui_phone').value=ui.phone||'';$('#ui_email').value=ui.email||'';
  $('#s_sudo').checked=!!SET.sudo_allowed;$('#sudoPwWrap').classList.toggle('hidden',!SET.sudo_allowed);
  $('#a_theme').value=themePref();
  $('#a_mode').value=MODE;
  renderProviders();renderLadder();renderRoleLadders();
  await loadCtf();
  await loadToolbox();
  showTab(tab||'userinfo');
  $('#settings').classList.remove('hidden');
}
function providersMap(){
  const m={};
  HTTP.forEach(p=>{if(!p.name)return;const c={backend:'http_api',api:p.api,model:p.model};if(p.endpoint)c.endpoint=p.endpoint;
    if(p.mode==='env'){if(p.key)c.key_env=p.key;} else {if(p.key)c.api_key=p.key;}m[p.name]=c;});
  SUB.forEach(p=>{if(!p.name)return;const c={backend:'cli',cmd:p.cmd||p.name};const mf=(PSTATUS[p.name]||{}).model_flag;if(mf)c.model_flag=mf;m[p.name]=c;});
  OLLAMA.forEach(p=>{if(!p.name)return;const c={backend:'ollama',model:p.model||'llama3.1'};if(p.endpoint)c.endpoint=p.endpoint;m[p.name]=c;});
  return m;
}
$('#setsave').onclick=async()=>{
  syncFromDom();reconcileLadder();reconcileRoleLadders();
  const pref=[]; LADDER.forEach(e=>{if(!pref.includes(e.provider))pref.push(e.provider);});  // compat
  const reasoning={providers:providersMap(),ladder:LADDER,preference:pref,
    policy:{map:$('#pol_map').value,exploit:$('#pol_exploit').value,report:$('#pol_report').value},
    roles: Object.fromEntries(Object.entries(ROLE_LADDERS)
        .filter(([role,l])=>l && l.length)
        .map(([role,l])=>[role,{ladder:l}]))};
  const name=$('#ui_name').value.trim();
  const user_info={name,company:$('#ui_company').value.trim(),phone:$('#ui_phone').value.trim(),email:$('#ui_email').value.trim()};
  const body={user_info,pentester_name:name,sudo_allowed:$('#s_sudo').checked,reasoning};
  const r=await api('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  SET=r;decompose();renderProviders();renderLadder();renderRoleLadders();
  $('#setmsg').textContent='Saved ✓';setTimeout(()=>$('#setmsg').textContent='',1500);
};
$('#a_theme').onchange=()=>{const v=$('#a_theme').value;applyTheme(v);try{localStorage.setItem('atpt_theme',v);}catch(e){}};
$('#a_mode').onchange=async()=>{const m=$('#a_mode').value; if(!ENG){$('#a_modemsg').textContent='select an engagement first';return;}
  await api('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({eng:ENG,mode:m})});
  MODE=m; const e=ENGS.find(x=>x.id===ENG); if(e)e.mode=m; $('#a_modemsg').textContent='mode set to '+m+' ✓';setTimeout(()=>$('#a_modemsg').textContent='',1500);};
$('#rp_dl').onclick=downloadReport;
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
  ['#c_goals','#c_osint','#c_vpn','#c_ab_host','#c_ab_user','#c_ab_pw','#c_ab_key'].forEach(s=>$(s).value='');
  if(!ENG)return;
  const c=await api('/api/settings/ctf?eng='+encodeURIComponent(ENG));
  $('#c_goals').value=c.goals||'';$('#c_osint').value=(c.osint||{}).context||'';$('#c_vpn').value=c.vpn_config_path||'';
  const ab=c.attackbox||{};$('#c_ab_host').value=ab.host||'';$('#c_ab_user').value=ab.user||'';$('#c_ab_key').value=ab.key_path||'';
  $('#c_ab_pw').placeholder=c.attackbox_has_password?'•••••• set this session':'••••••••';
  const oa=c.offensive_agent||{};$('#c_agent').checked=!!oa.enabled;
  $('#c_agent_steps').value=oa.max_steps||20;$('#c_agent_bins').value=(oa.allow_bins||[]).join(', ');
  vpnStatus();
}
$('#ctfSave').onclick=async()=>{
  if(!ENG){$('#ctfMsg').textContent='no engagement selected';return;}
  const body={goals:$('#c_goals').value,osint_context:$('#c_osint').value,vpn_config_path:$('#c_vpn').value.trim(),
    attackbox:{host:$('#c_ab_host').value.trim(),user:$('#c_ab_user').value.trim(),
               password:$('#c_ab_pw').value,key_path:$('#c_ab_key').value.trim()},
    offensive_agent:{enabled:$('#c_agent').checked,max_steps:parseInt($('#c_agent_steps').value)||20,
      allow_bins:$('#c_agent_bins').value.split(',').map(s=>s.trim()).filter(Boolean)}};
  const r=await api('/api/settings/ctf?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.error){$('#ctfMsg').textContent='⚠ '+r.error;return;}
  $('#c_ab_pw').value='';$('#ctfMsg').textContent='Saved ✓';setTimeout(()=>$('#ctfMsg').textContent='',1500);
};

/* ---- strategy toolbox (learned skills) ---- */
function renderToolbox(skills){
  $('#tbList').innerHTML=(skills||[]).map(s=>{
    const tags=((s.applies_to&&s.applies_to.service_tags)||[]).map(t=>`<span class="badge">${esc(t)}</span>`).join(' ');
    return `<li><span class="nm"><b>${esc(s.name)}</b> ${tags}<br><span class="hint">${esc(s.success_note||'')}</span></span>
      <button class="ghost tb_del" data-name="${esc(s.name)}">✕</button></li>`;
  }).join('')||'<div class="hint">No skills yet — run the agent to a win.</div>';
  $('#tbList').querySelectorAll('.tb_del').forEach(b=>b.onclick=async()=>{
    await api('/api/toolbox?name='+encodeURIComponent(b.dataset.name),{method:'DELETE'});
    loadToolbox();
  });
}
async function loadToolbox(){
  const {skills}=await api('/api/toolbox');
  renderToolbox(skills);
}

/* ---- file picker (upload -> server path) + background VPN ---- */
function fileToB64(file){return new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(file);});}
async function uploadPicked(file){ if(!ENG)return {error:'select an engagement first'};
  const b64=await fileToB64(file);
  return api('/api/upload?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:file.name,content_b64:b64})});
}
let VPNPOLL=null;
async function vpnStatus(){ const s=await api('/api/vpn/status');
  const m={down:'○ down',connecting:'◐ connecting…',connected:'● connected',error:'⚠ '+(s.error||'error')};
  $('#vpnStatus').textContent=m[s.status]||s.status;
  if(s.status!=='connecting'&&VPNPOLL){clearInterval(VPNPOLL);VPNPOLL=null;} return s.status; }
$('#c_vpn_pick')&&($('#c_vpn_pick').onclick=()=>$('#c_vpn_file').click());
$('#c_vpn_file')&&($('#c_vpn_file').onchange=async e=>{const f=e.target.files[0]; if(!f)return;
  $('#c_vpn').value='uploading…'; const r=await uploadPicked(f);
  if(r.error){$('#c_vpn').value='';$('#ctfMsg').textContent='⚠ '+esc(r.error);return;}
  $('#c_vpn').value=r.path;
  await api('/api/settings/ctf?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vpn_config_path:r.path})});
  $('#ctfMsg').textContent='VPN config saved ✓';setTimeout(()=>$('#ctfMsg').textContent='',1500);});
$('#vpnConnect')&&($('#vpnConnect').onclick=async()=>{ if(!ENG){$('#ctfMsg').textContent='select an engagement';return;}
  $('#vpnStatus').textContent='starting…';
  let r=await api('/api/vpn/connect?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  if(r.needs_sudo){ const pw=prompt('sudo password (to start OpenVPN in the background):'); if(!pw){$('#vpnStatus').textContent='cancelled';return;}
    r=await api('/api/vpn/connect?eng='+encodeURIComponent(ENG),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sudo_password:pw})}); }
  if(r.error){$('#vpnStatus').textContent='⚠ '+esc(r.error);return;}
  chat('sys','🔌 VPN starting in the background…'); if(VPNPOLL)clearInterval(VPNPOLL); VPNPOLL=setInterval(vpnStatus,2000); vpnStatus();});
$('#vpnDisconnect')&&($('#vpnDisconnect').onclick=async()=>{await api('/api/vpn/disconnect',{method:'POST'});vpnStatus();});

$('#menubtn').onclick=()=>openSettings();
$('#menuScope').onclick=()=>openSettings('scope');
$('#setclose').onclick=()=>$('#settings').classList.add('hidden');
$('#settings').onclick=e=>{if(e.target.id==='settings')$('#settings').classList.add('hidden');};

chat('sys','Welcome. Step 1: define scope &amp; target (or <b>Load demo</b>). Step 2: <b>run</b>. Then download the PTES report.');
refreshEngagements().then(pollRun);
setInterval(()=>{if(ENG)refreshStatus()},2500);
</script>
</body></html>"""
