"""Stdlib web UI for ATPTmaster — chat-driven control + findings + attack tree +
PTES report download. No third-party deps: http.server + a single embedded page.

Routing lives in `WebApp.handle(method, path, query, body) -> (status, ctype, bytes, headers)`
so it is unit-testable without opening a socket. `serve()` wraps it in a threading
HTTP server; each request opens its own SQLite connection (thread-safe by construction).
Binds to 127.0.0.1 by default — this is an operator console, not a public endpoint.
"""
from __future__ import annotations
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .engine import Orchestrator
from .registry import discover
from .state import SQLiteStore

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_report_builder(project_dir: Path):
    p = Path(project_dir) / "modules" / "report_ptes" / "module.py"
    spec = importlib.util.spec_from_file_location("report_ptes_web", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_report_md


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
        except Exception as exc:  # never 500-crash the console
            return self._json(500, {"error": str(exc)})

    def _route(self, method, path, query, body):
        if method == "GET" and path in ("/", "/index.html"):
            return 200, "text/html; charset=utf-8", INDEX_HTML.encode(), {}

        if path == "/api/engagements" and method == "GET":
            return self._json(200, {"engagements": self._store().list_engagements()})

        if path == "/api/engagement" and method == "POST":
            return self._create_engagement(json.loads(body or b"{}"))

        if path == "/api/demo" and method == "POST":
            return self._create_demo()

        eid = query.get("eng") or (json.loads(body or b"{}").get("eng") if method == "POST" else None)
        if path.startswith("/api/") and not eid:
            return self._json(400, {"error": "missing 'eng' (engagement id)"})
        store = self._store()
        if not store.get_engagement(eid):
            return self._json(404, {"error": f"no engagement '{eid}'"})

        if path == "/api/status" and method == "GET":
            return self._json(200, self._status_obj(store, eid))
        if path == "/api/findings" and method == "GET":
            rows = [{**f, "evidence": _parse_evidence(f)} for f in store.list_findings(eid)]
            return self._json(200, {"findings": rows})
        if path == "/api/tree" and method == "GET":
            return self._json(200, self._tree(store, eid))
        if path == "/api/run" and method == "POST":
            data = json.loads(body or b"{}")
            mode = data.get("mode") or store.get_engagement(eid)["mode"]
            res = self._orch(store).run(store.get_engagement(eid), mode, dry_run=bool(data.get("dry_run")))
            return self._json(200, {"result": res, "status": self._status_obj(store, eid)})
        if path == "/api/approve" and method == "POST":
            data = json.loads(body or b"{}")
            store.resolve_approval(eid, data.get("module"), "approved")
            store.add_event(eid, None, data.get("module"), "info", "approval_resolved",
                            f"module '{data.get('module')}' approved via UI", None)
            return self._json(200, {"status": self._status_obj(store, eid)})
        if path == "/api/chat" and method == "POST":
            return self._chat(store, eid, json.loads(body or b"{}").get("message", ""))
        if path == "/api/report" and method == "GET":
            md = _load_report_builder(self.project_dir)(store, eid, self.project_dir)
            safe = "".join(c for c in eid if c.isalnum() or c in "-_") or "engagement"
            return (200, "text/markdown; charset=utf-8", md.encode(),
                    {"Content-Disposition": f'attachment; filename="{safe}-ptes-report.md"'})

        return self._json(404, {"error": f"no route {method} {path}"})

    def _create_engagement(self, data):
        eid = (data.get("engagement") or "").strip()
        scope = data.get("scope") or {}
        has_target = bool(scope.get("in_scope_domains") or scope.get("in_scope_cidrs"))
        if not eid:
            return self._json(400, {"error": "engagement id is required"})
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
                reply = f"approved {parts[1]} — send 'run' to continue."
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

    class Handler(BaseHTTPRequestHandler):
        def _do(self, method):
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
<style>
:root{--bg:#0d1117;--panel:#161b22;--edge:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#2f81f7;
--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#3fb950;--val:#3fb950;--cand:#d29922;--fp:#6e7681}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--edge);background:var(--panel)}
header b{font-size:16px}header .sp{flex:1}
select,input,button,textarea{font:inherit;color:var(--fg);background:#0d1117;border:1px solid var(--edge);border-radius:6px;padding:6px 8px}
button{background:var(--acc);border-color:var(--acc);color:#fff;cursor:pointer}button.ghost{background:#0d1117;color:var(--fg)}
button:hover{filter:brightness(1.1)}button:disabled{opacity:.5;cursor:not-allowed}
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px;max-width:1300px;margin:0 auto}
.col{display:flex;flex-direction:column;gap:12px;min-width:0}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:10px;padding:12px}
.card h3{margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
#chatlog{height:300px;overflow:auto;display:flex;flex-direction:column;gap:8px;padding-right:4px}
.msg{padding:8px 10px;border-radius:8px;max-width:90%}
.msg.me{align-self:flex-end;background:#1f6feb33;border:1px solid #1f6feb55}
.msg.sys{align-self:flex-start;background:#0d1117;border:1px solid var(--edge)}
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
.hidden{display:none}
@media(max-width:900px){.wrap{grid-template-columns:1fr}}
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
</header>

<div class="wrap">
  <div class="col">
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

<script>
const $=s=>document.querySelector(s), api=(p,o)=>fetch(p,o).then(r=>r.json());
let ENG=null;
const eng=()=>ENG;
function esc(s){return (s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
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
  const rows=findings.map(f=>`<tr><td><span class="pill sev-${(f.severity||'info')}">${esc(f.severity||'info')}</span></td>
    <td>${esc(f.title)}<div class=muted style="font-size:11px">${esc((f.evidence&&f.evidence.asset_value)||f.source_tool||'')}</div></td>
    <td class="st-${f.status}">${esc(f.status)}</td><td>${esc(f.owasp||'—')}</td><td>${f.cvss??'—'}</td></tr>`).join('');
  $('#findings').innerHTML=`<table><tr><th>Sev</th><th>Finding</th><th>Status</th><th>OWASP</th><th>CVSS</th></tr>${rows}</table>`;
}
async function refreshTree(){
  const t=await api('/api/tree?eng='+encodeURIComponent(ENG));
  if(!t.branches||!t.branches.length){$('#tree').innerHTML='<span class=muted>—</span>';return}
  $('#tree').innerHTML=`<div class=muted>🎯 ${esc(t.target)}</div>`+t.branches.map(b=>
    `<div class=branch><div class=dom>▸ ${esc(b.domain)} <span class=muted>(${b.findings.length})</span></div>
     <ul>${b.findings.map(f=>`<li><span class="pill sev-${(f.severity||'info')}">${esc(f.severity)}</span>
       ${esc(f.title)} <span class="st-${f.status} muted">${esc(f.status)}</span></li>`).join('')}</ul></div>`).join('');
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

chat('sys','Welcome. Step 1: define scope &amp; target (or <b>Load demo</b>). Step 2: <b>run</b>. Then download the PTES report.');
refreshEngagements();
setInterval(()=>{if(ENG)refreshStatus()},2500);
</script>
</body></html>"""
