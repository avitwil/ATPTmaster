"""Strategy Toolbox: learned skills persisted as hand-editable JSON files (the
source of truth) plus a rebuildable SQLite index for fast tag retrieval. A skill
is a distilled SUCCESSFUL trajectory; it only ever SUGGESTS commands — every
command it yields is still vetted by ScopeGuard at execution time, so a skill can
never widen scope or the allow-list. Stdlib-only, cross-engagement, portable:
copy the toolbox/ dir elsewhere and reindex() rebuilds the index."""
from __future__ import annotations
import json
import re
import sqlite3
import time
from pathlib import Path

_SLUG = re.compile(r"[^a-z0-9]+")
_INDEX = "index.db"


def slugify(name: str) -> str:
    s = _SLUG.sub("-", (name or "").strip().lower()).strip("-")
    return s or "skill"


def _norm_tags(v) -> list[str]:
    if isinstance(v, str):
        v = [v]
    return sorted({str(x).strip().lower() for x in (v or []) if str(x).strip()})


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Toolbox:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._cx = None

    # --- files (source of truth) --------------------------------------------
    def path_for(self, name: str) -> Path:
        return self.root / f"{slugify(name)}.json"

    def list_skills(self) -> list[dict]:
        out = []
        for p in sorted(self.root.glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except Exception:
                continue
        return out

    def get(self, name: str):
        p = self.path_for(name)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text())
        except Exception:
            return None

    def save(self, skill: dict):
        name = str(skill.get("name") or "").strip()
        raw_steps = skill.get("steps") or []
        steps = [{"command": [str(x) for x in (s.get("command") or [])],
                  "note": str(s.get("note") or "")}
                 for s in raw_steps if s.get("command")]
        if not name or not steps:
            return None
        rec = {
            "name": name,
            "applies_to": {
                "goal_tags": _norm_tags((skill.get("applies_to") or {}).get("goal_tags")),
                "service_tags": _norm_tags((skill.get("applies_to") or {}).get("service_tags")),
            },
            "steps": steps,
            "provenance": skill.get("provenance") or {},
            "success_note": str(skill.get("success_note") or ""),
            "updated_at": skill.get("updated_at") or _now(),
        }
        p = self.path_for(name)
        p.write_text(json.dumps(rec, indent=2, ensure_ascii=False))
        self._index_one(rec, p)
        return p

    def delete(self, name: str) -> bool:
        p = self.path_for(name)
        existed = p.exists()
        if existed:
            p.unlink()
        db = self._db()
        db.execute("DELETE FROM skills WHERE name=?", (slugify(name),))
        db.commit()
        return existed

    # --- index (rebuildable accelerator) ------------------------------------
    def _db(self):
        if self._cx is None:
            self._cx = sqlite3.connect(str(self.root / _INDEX))
            self._cx.execute(
                "CREATE TABLE IF NOT EXISTS skills (name TEXT PRIMARY KEY, path TEXT, "
                "goal_tags TEXT, service_tags TEXT, success_note TEXT, updated_at TEXT)")
            self._cx.commit()
        return self._cx

    def _index_one(self, rec: dict, p: Path):
        db = self._db()
        db.execute(
            "INSERT INTO skills (name,path,goal_tags,service_tags,success_note,updated_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET path=excluded.path, "
            "goal_tags=excluded.goal_tags, service_tags=excluded.service_tags, "
            "success_note=excluded.success_note, updated_at=excluded.updated_at",
            (slugify(rec["name"]), str(p),
             " ".join(rec["applies_to"]["goal_tags"]),
             " ".join(rec["applies_to"]["service_tags"]),
             rec.get("success_note", ""), rec.get("updated_at", "")))
        db.commit()

    def reindex(self) -> int:
        db = self._db()
        db.execute("DELETE FROM skills")
        db.commit()
        n = 0
        for p in sorted(self.root.glob("*.json")):
            try:
                rec = json.loads(p.read_text())
            except Exception:
                continue
            ap = rec.get("applies_to") or {}
            rec["applies_to"] = {"goal_tags": _norm_tags(ap.get("goal_tags")),
                                 "service_tags": _norm_tags(ap.get("service_tags"))}
            rec.setdefault("success_note", "")
            rec.setdefault("updated_at", "")
            self._index_one(rec, p)
            n += 1
        return n
