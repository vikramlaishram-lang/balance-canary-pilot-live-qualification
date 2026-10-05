"""Single-host SQLite durability. A transaction reserves intent before dispatch."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .contracts import Rejected, digest, require


class Store:
    def __init__(self, path, writer=False):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY, digest TEXT NOT NULL, target TEXT NOT NULL,
                    state TEXT NOT NULL, document TEXT NOT NULL, updated INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL, event TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
            """)
            if writer:
                db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_unresolved_target
                    ON records(target) WHERE state IN ('RESERVED','SUBMITTED','UNKNOWN')""")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def decode(row):
        if row is None:
            return None
        return {"id": row["id"], "digest": row["digest"], "state": row["state"],
                "document": json.loads(row["document"]), "updated": row["updated"]}

    def get(self, record_id):
        with self.connect() as db:
            return self.decode(db.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone())

    def list(self):
        with self.connect() as db:
            return [self.decode(r) for r in db.execute("SELECT * FROM records ORDER BY updated,id")]

    def event(self, db, record_id, state, document):
        previous = db.execute("SELECT hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        event = {"state": state, "document": document, "at": int(time.time())}
        hashed = digest({"previous": previous, "record_id": record_id, "event": event})
        db.execute("INSERT INTO events(record_id,event,previous,hash) VALUES(?,?,?,?)",
                   (record_id, json.dumps(event, sort_keys=True), previous, hashed))

    def create(self, record_id, intent_digest, target, state, document):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = self.decode(db.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone())
            if existing:
                require(existing["digest"] == intent_digest, "IDEMPOTENCY_KEY_REUSE_MISMATCH")
                return existing, False
            try:
                db.execute("INSERT INTO records VALUES(?,?,?,?,?,?)", (record_id, intent_digest, target, state,
                           json.dumps(document), int(time.time())))
            except sqlite3.IntegrityError as exc:
                raise Rejected("TARGET_HAS_UNRESOLVED_INTENT") from exc
            self.event(db, record_id, state, document)
        return self.get(record_id), True

    def update(self, record_id, state, document, expected_states=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = self.decode(db.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone())
            require(existing is not None, "unknown objective")
            if expected_states is not None and existing["state"] not in expected_states:
                return existing
            db.execute("UPDATE records SET state=?,document=?,updated=? WHERE id=?",
                       (state, json.dumps(document), int(time.time()), record_id))
            self.event(db, record_id, state, document)
        return self.get(record_id)

    def export(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY sequence")]

    def verify_history(self):
        previous = "0" * 64
        for row in self.export():
            require(row["previous"] == previous, "history link changed")
            require(row["hash"] == digest({"previous": previous, "record_id": row["record_id"],
                                           "event": json.loads(row["event"])}), "history content changed")
            previous = row["hash"]
        return previous
