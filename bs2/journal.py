"""Per-assessment receipts. Hash chaining detects accidental edits, not a hostile owner.

The journal is authoritative; Cairn is a rebuildable, provenance-preserving projection.
No credentials, commands, response bodies, or model prompts belong in this journal.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from contextlib import contextmanager


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Journal:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.stat().st_mode & 0o077:
            raise ValueError("session directory must be private (chmod 700)")
        self.db = self.directory / "receipts.sqlite3"
        with self.connect() as con:
            con.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            con.execute("INSERT OR IGNORE INTO metadata VALUES('battle_id', ?)", (os.urandom(16).hex(),))
            self.battle_id = con.execute("SELECT value FROM metadata WHERE key='battle_id'").fetchone()[0]
            con.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, "
                        "kind TEXT NOT NULL, payload TEXT NOT NULL, ts REAL NOT NULL, "
                        "previous TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)")
        os.chmod(self.db, 0o600)

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.db, timeout=15)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    def events(self):
        with self.connect() as con:
            rows = [dict(r) for r in con.execute("SELECT * FROM events ORDER BY seq")]
        previous = "0" * 64
        for seq, row in enumerate(rows, 1):
            row["payload"] = json.loads(row["payload"])
            claimed = row.pop("hash")
            if row["seq"] != seq or row["previous"] != previous or digest(row) != claimed:
                raise ValueError("receipt chain integrity failure")
            row["hash"] = claimed
            previous = claimed
        return rows

    def append(self, kind, payload):
        self.events()  # fail closed on damaged history
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            last = con.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            row = {"seq": last["seq"] + 1 if last else 1, "kind": kind,
                   "payload": payload, "ts": time.time(),
                   "previous": last["hash"] if last else "0" * 64}
            row["hash"] = digest(row)
            con.execute("INSERT INTO events VALUES(?,?,?,?,?,?)",
                        (row["seq"], kind, canonical(payload), row["ts"], row["previous"], row["hash"]))
        return row
