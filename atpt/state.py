"""State Tree store. SQLite adapter (portable default). Same shape as
db/schema.sql so a Postgres adapter can implement this interface unchanged."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
  id          TEXT PRIMARY KEY,
  name        TEXT,
  scope       TEXT,               -- JSON snapshot
  scope_file  TEXT,
  status      TEXT DEFAULT 'active',
  mode        TEXT DEFAULT 'step',
  config      TEXT,               -- JSON (recon_tools, rate, ...)
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assets (
  id            INTEGER PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  asset_type    TEXT NOT NULL,
  value         TEXT NOT NULL,
  host TEXT, ip TEXT, port INTEGER, protocol TEXT,
  service TEXT, product TEXT, version TEXT,
  http_status INTEGER, http_title TEXT,
  tech TEXT, url TEXT, source_tool TEXT, raw TEXT,
  first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
  last_seen  TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (engagement_id, asset_type, value)
);
CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  asset_id      INTEGER,
  title TEXT NOT NULL, domain TEXT, severity TEXT,
  cvss REAL, owasp TEXT, status TEXT DEFAULT 'candidate',
  evidence TEXT, source_tool TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, engagement_id TEXT, ts TEXT DEFAULT CURRENT_TIMESTAMP,
  phase TEXT, module TEXT, level TEXT, kind TEXT, message TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY, engagement_id TEXT, module TEXT, phase TEXT,
  status TEXT DEFAULT 'pending', reason TEXT,
  requested_at TEXT DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS module_runs (
  id INTEGER PRIMARY KEY, engagement_id TEXT, module TEXT, phase TEXT,
  status TEXT, summary TEXT, error TEXT,
  finished_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

_ASSET_COLS = ["asset_type", "value", "host", "ip", "port", "protocol", "service",
               "product", "version", "http_status", "http_title", "tech", "url",
               "source_tool", "raw"]


class SQLiteStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.cx = sqlite3.connect(str(self.db_path))
        self.cx.row_factory = sqlite3.Row
        self.cx.execute("PRAGMA foreign_keys=ON")
        self.cx.executescript(SCHEMA)
        self.cx.commit()

    # --- engagements ---------------------------------------------------------
    def create_engagement(self, eid, name, scope: dict, scope_file, mode, config: dict):
        self.cx.execute(
            "INSERT INTO engagements (id,name,scope,scope_file,mode,config) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "name=excluded.name, scope=excluded.scope, scope_file=excluded.scope_file, "
            "mode=excluded.mode, config=excluded.config",
            (eid, name, json.dumps(scope), str(scope_file), mode, json.dumps(config)))
        self.cx.commit()

    def get_engagement(self, eid) -> dict | None:
        r = self.cx.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
        return dict(r) if r else None

    def set_mode(self, eid, mode):
        self.cx.execute("UPDATE engagements SET mode=? WHERE id=?", (mode, eid))
        self.cx.commit()

    # --- assets / findings ---------------------------------------------------
    def upsert_asset(self, eid, a: dict):
        vals = [a.get(c) for c in _ASSET_COLS]
        for i, c in enumerate(_ASSET_COLS):
            if c in ("tech", "raw") and isinstance(vals[i], (dict, list)):
                vals[i] = json.dumps(vals[i])
        sets = ", ".join(f"{c}=excluded.{c}" for c in _ASSET_COLS if c not in ("asset_type", "value"))
        self.cx.execute(
            f"INSERT INTO assets (engagement_id,{','.join(_ASSET_COLS)},last_seen) "
            f"VALUES (?,{','.join('?' for _ in _ASSET_COLS)},CURRENT_TIMESTAMP) "
            f"ON CONFLICT(engagement_id,asset_type,value) DO UPDATE SET {sets}, last_seen=CURRENT_TIMESTAMP",
            [eid, *vals])
        self.cx.commit()

    def upsert_finding(self, eid, f: dict):
        self.cx.execute(
            "INSERT INTO findings (engagement_id,asset_id,title,domain,severity,cvss,owasp,status,evidence,source_tool) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (eid, f.get("asset_id"), f.get("title"), f.get("domain"), f.get("severity"),
             f.get("cvss"), f.get("owasp"), f.get("status", "candidate"),
             json.dumps(f.get("evidence")) if f.get("evidence") else None, f.get("source_tool")))
        self.cx.commit()

    def count_assets(self, eid) -> int:
        return self.cx.execute("SELECT count(*) FROM assets WHERE engagement_id=?", (eid,)).fetchone()[0]

    def list_assets(self, eid) -> list[dict]:
        return [dict(r) for r in self.cx.execute(
            "SELECT * FROM assets WHERE engagement_id=? ORDER BY id", (eid,))]

    def count_findings(self, eid, status=None) -> int:
        if status:
            return self.cx.execute("SELECT count(*) FROM findings WHERE engagement_id=? AND status=?",
                                   (eid, status)).fetchone()[0]
        return self.cx.execute("SELECT count(*) FROM findings WHERE engagement_id=?", (eid,)).fetchone()[0]

    def asset_type_counts(self, eid) -> list[tuple]:
        return [tuple(r) for r in self.cx.execute(
            "SELECT asset_type, count(*) FROM assets WHERE engagement_id=? GROUP BY 1 ORDER BY 2 DESC", (eid,))]

    # --- events --------------------------------------------------------------
    def add_event(self, eid, phase, module, level, kind, message, data):
        self.cx.execute(
            "INSERT INTO events (engagement_id,phase,module,level,kind,message,data) VALUES (?,?,?,?,?,?,?)",
            (eid, phase, module, level, kind, message, json.dumps(data) if data else None))
        self.cx.commit()

    def recent_events(self, eid, limit=15) -> list[dict]:
        return [dict(r) for r in self.cx.execute(
            "SELECT ts,phase,module,level,kind,message FROM events WHERE engagement_id=? "
            "ORDER BY id DESC LIMIT ?", (eid, limit))]

    # --- approvals -----------------------------------------------------------
    def request_approval(self, eid, module, phase, reason):
        row = self.cx.execute(
            "SELECT id FROM approvals WHERE engagement_id=? AND module=? AND status='pending'",
            (eid, module)).fetchone()
        if row:
            return row[0]
        cur = self.cx.execute(
            "INSERT INTO approvals (engagement_id,module,phase,reason) VALUES (?,?,?,?)",
            (eid, module, phase, reason))
        self.cx.commit()
        return cur.lastrowid

    def is_approved(self, eid, module) -> bool:
        r = self.cx.execute(
            "SELECT 1 FROM approvals WHERE engagement_id=? AND module=? AND status='approved' LIMIT 1",
            (eid, module)).fetchone()
        return bool(r)

    def pending_approvals(self, eid) -> list[dict]:
        return [dict(r) for r in self.cx.execute(
            "SELECT id,module,phase,reason FROM approvals WHERE engagement_id=? AND status='pending'", (eid,))]

    def resolve_approval(self, eid, module, decision):
        self.cx.execute(
            "UPDATE approvals SET status=?, resolved_at=CURRENT_TIMESTAMP "
            "WHERE engagement_id=? AND module=? AND status='pending'", (decision, eid, module))
        self.cx.commit()

    # --- module runs ---------------------------------------------------------
    def log_module_run(self, eid, module, phase, status, summary="", error=""):
        self.cx.execute(
            "INSERT INTO module_runs (engagement_id,module,phase,status,summary,error) VALUES (?,?,?,?,?,?)",
            (eid, module, phase, status, summary, error))
        self.cx.commit()

    def completed_modules(self, eid) -> set:
        return {r[0] for r in self.cx.execute(
            "SELECT DISTINCT module FROM module_runs WHERE engagement_id=? AND status='ok'", (eid,))}
