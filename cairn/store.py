"""CairnStore — the durable, append-only, layered memory unit.

A *cairn* is a curated stack scoped to ONE entity (a host, a BS2 engine, a design
thread, a person). Each item lives in a layer and is staleness-stamped and tagged
hypothesis|verified (that tag IS INV-6 — "recall suggests" vs "I proved it"; the
nervous system must never blur it). The store is SEPARATE from BS2 telemetry and is
never opened against a live campaign db.

Non-negotiables baked into the schema (from om-d6's lived-pain spec + Cairn DIRECTIVE #1):
  - APPEND-ONLY content: fold() only inserts; a changed fact is a SUPERSESSION, not an
    overwrite. Triggers forbid deleting rows or mutating content/entity/kind/folded_at.
  - IDEMPOTENT fold keyed by (entity, fold_key) so replay/re-ingest never duplicates.
  - PROVENANCE: every item carries source + as_of so a consumer can re-verify cheaply.
"""
from __future__ import annotations
import os
import sqlite3
from dataclasses import dataclass
from typing import Iterable, Optional

from .provenance import now_iso

DEFAULT_DB = os.environ.get("CAIRN_DB", os.path.expanduser("~/.local/state/bs2/cairn.sqlite3"))

# layers
STATE, HISTORY, DISTILLED, NEGATIVE = "state", "history", "distilled", "negative"
LAYERS = (STATE, HISTORY, DISTILLED, NEGATIVE)

# rank hints used by the assembler when packing to a budget
DEFAULT_VALUE = {
    "invariant": 10, "flag": 9, "credential": 8, "wired_state": 7,
    "lesson": 6, "host": 5, "fact": 5, "thread": 4, "negative": 4,
    "tool": 3, "evidence": 2, "event": 1,
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cairn_items(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  entity        TEXT NOT NULL,
  layer         TEXT NOT NULL,
  kind          TEXT NOT NULL,
  content       TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'hypothesis',   -- hypothesis|verified (INV-6)
  source        TEXT,                                 -- file:..|event:..|sigil:..|url:..
  as_of         TEXT,                                 -- when established / last verified
  folded_at     TEXT NOT NULL,                        -- append time (immutable)
  fold_key      TEXT,                                 -- idempotency key
  value         INTEGER NOT NULL DEFAULT 2,
  confidence    REAL,
  superseded_by INTEGER                               -- newer item id; NULL = live
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_fold ON cairn_items(entity, fold_key)
  WHERE fold_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_live ON cairn_items(entity, kind) WHERE superseded_by IS NULL;

CREATE TRIGGER IF NOT EXISTS cairn_no_delete
BEFORE DELETE ON cairn_items
BEGIN SELECT RAISE(ABORT, 'cairn items are append-only: no delete (supersede instead)'); END;

CREATE TRIGGER IF NOT EXISTS cairn_no_content_mutation
BEFORE UPDATE ON cairn_items
WHEN OLD.content <> NEW.content OR OLD.entity <> NEW.entity
  OR OLD.kind <> NEW.kind OR OLD.folded_at <> NEW.folded_at
BEGIN SELECT RAISE(ABORT, 'cairn content is append-only: supersede, do not overwrite'); END;
"""


@dataclass
class Item:
    id: int
    entity: str
    layer: str
    kind: str
    content: str
    status: str
    source: Optional[str]
    as_of: Optional[str]
    folded_at: str
    fold_key: Optional[str]
    value: int
    confidence: Optional[float]
    superseded_by: Optional[int]

    @property
    def verified(self) -> bool:
        return self.status == "verified"


class CairnStore:
    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.con = sqlite3.connect(db_path)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.executescript(_SCHEMA)
        self.con.commit()

    def close(self):
        self.con.close()

    # ---- write path (Curator uses this) ----
    def fold(self, entity: str, content: str, kind: str, *, layer: str = STATE,
             status: str = "hypothesis", source: Optional[str] = None,
             as_of: Optional[str] = None, fold_key: Optional[str] = None,
             value: Optional[int] = None, confidence: Optional[float] = None) -> int:
        """Append-only, idempotent insert. Returns the item id (existing one if idempotent)."""
        if layer not in LAYERS:
            raise ValueError(f"unknown layer {layer!r}")
        if status not in ("hypothesis", "verified"):
            raise ValueError(f"status must be hypothesis|verified, got {status!r}")
        content = content.strip()
        if not content:
            raise ValueError("empty content")
        as_of = as_of or now_iso()
        value = DEFAULT_VALUE.get(kind, 2) if value is None else value

        # idempotency by explicit key
        if fold_key is not None:
            row = self.con.execute(
                "SELECT id FROM cairn_items WHERE entity=? AND fold_key=?",
                (entity, fold_key)).fetchone()
            if row:
                return row["id"]
        # idempotency by identical live content (replay safety without a key)
        row = self.con.execute(
            "SELECT id FROM cairn_items WHERE entity=? AND kind=? AND content=? "
            "AND status=? AND source IS ? AND superseded_by IS NULL",
            (entity, kind, content, status, source)).fetchone()
        if row:
            return row["id"]

        cur = self.con.execute(
            "INSERT INTO cairn_items(entity,layer,kind,content,status,source,as_of,"
            "folded_at,fold_key,value,confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (entity, layer, kind, content, status, source, as_of, now_iso(),
             fold_key, value, confidence))
        self.con.commit()
        return cur.lastrowid

    def supersede(self, old_id: int, new_id: int) -> None:
        """State-preserving replacement: mark old item superseded by new (no overwrite)."""
        self.con.execute("UPDATE cairn_items SET superseded_by=? WHERE id=?", (new_id, old_id))
        self.con.commit()

    def verify(self, item_id: int, as_of: Optional[str] = None) -> None:
        """Promote hypothesis -> verified (INV-6) and refresh the as_of stamp."""
        self.con.execute("UPDATE cairn_items SET status='verified', as_of=? WHERE id=?",
                         (as_of or now_iso(), item_id))
        self.con.commit()

    # ---- read path (Assembler uses this) ----
    def _rows(self, where: str, args: tuple) -> list[Item]:
        rows = self.con.execute(f"SELECT * FROM cairn_items WHERE {where}", args).fetchall()
        return [Item(**dict(r)) for r in rows]

    def live(self, entity: Optional[str] = None, kind: Optional[str] = None,
             layer: Optional[str] = None) -> list[Item]:
        where = ["superseded_by IS NULL"]
        args: list = []
        if entity is not None:
            where.append("entity=?"); args.append(entity)
        if kind is not None:
            where.append("kind=?"); args.append(kind)
        if layer is not None:
            where.append("layer=?"); args.append(layer)
        return self._rows(" AND ".join(where), tuple(args))

    def relevant(self, frontier: Iterable[str]) -> list[Item]:
        """Live items whose entity matches the current frontier (exact or substring)."""
        frontier = [f for f in frontier if f]
        items = self.live()
        if not frontier:
            return items
        keep = []
        for it in items:
            e = it.entity.lower()
            if any(f.lower() == e or f.lower() in e or e in f.lower() for f in frontier):
                keep.append(it)
        return keep

    def entities(self) -> list[str]:
        return [r["entity"] for r in self.con.execute(
            "SELECT DISTINCT entity FROM cairn_items WHERE superseded_by IS NULL").fetchall()]

    def conflicts(self, singleton_kinds=("wired_state",)) -> set[int]:
        """IDs of live items that contradict another live item of a SINGLETON kind.

        A singleton kind (e.g. wired_state: an engine is FIRES xor ORPHANED) must have one
        live truth per entity; two disagreeing live rows is a contradiction the slice should
        flag rather than serve both as [ok] (that is exactly the INV-6 failure). Normally empty
        because wire_state() supersedes, but a direct fold can create one.
        """
        contested: set[int] = set()
        for kind in singleton_kinds:
            rows = self.live(kind=kind)
            by_ent: dict[str, list[Item]] = {}
            for it in rows:
                by_ent.setdefault(it.entity, []).append(it)
            for ent, items in by_ent.items():
                if len({i.content for i in items}) > 1:
                    contested.update(i.id for i in items)
        return contested

    def stats(self) -> dict:
        total = self.con.execute("SELECT count(*) c FROM cairn_items").fetchone()["c"]
        live = self.con.execute(
            "SELECT count(*) c FROM cairn_items WHERE superseded_by IS NULL").fetchone()["c"]
        verified = self.con.execute(
            "SELECT count(*) c FROM cairn_items WHERE status='verified' "
            "AND superseded_by IS NULL").fetchone()["c"]
        return {"total_rows": total, "live": live, "verified": verified,
                "superseded": total - live, "entities": len(self.entities())}
