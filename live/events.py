#!/usr/bin/env python3
"""Append-only event ledger backing the Cartographer projection."""
from __future__ import annotations

import json
import os
from pathlib import Path

KINDS = {"fold", "verify", "refuse", "done", "exhausted", "dead", "evidence"}
FILENAME = "events.json"


class EventLedger:
    def __init__(self, run_dir=None, events=None):
        self.run_dir = Path(run_dir) if run_dir else None
        self.events = list(events or [])
        self._validate_scan()

    def _validate_scan(self):
        expected = 1
        for event in self.events:
            self._validate(event)
            if event["seq"] != expected:
                raise ValueError(f"non-contiguous event sequence at {event['seq']}")
            expected += 1

    @staticmethod
    def _validate(event):
        if not isinstance(event, dict) or set(event) != {"seq", "ts", "kind", "payload"}:
            raise ValueError("event requires exactly seq, ts, kind, payload")
        if not isinstance(event["seq"], int) or event["seq"] < 1:
            raise ValueError("event seq must be a positive integer")
        if not isinstance(event["ts"], int) or event["ts"] < 0:
            raise ValueError("event ts must be a non-negative integer")
        if event["kind"] not in KINDS:
            raise ValueError(f"unknown event kind: {event['kind']!r}")
        if not isinstance(event["payload"], dict):
            raise ValueError("event payload must be a dict")

    def append(self, event):
        value = dict(event or {})
        value.setdefault("seq", len(self.events) + 1)
        self._validate(value)
        if value["seq"] != len(self.events) + 1:
            raise ValueError("event seq must be the next contiguous sequence")
        self.events.append(value)
        return dict(value)

    def scan(self):
        return [dict(event, payload=dict(event["payload"])) for event in self.events]

    def save(self):
        if not self.run_dir:
            return
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / FILENAME
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"events": self.events}, indent=1))
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, run_dir):
        path = Path(run_dir) / FILENAME
        events = []
        if path.exists():
            raw = json.loads(path.read_text())
            events = raw.get("events", [])
        return cls(run_dir, events)


def rebuild_from_events(events, run_dir=None):
    """Replay ledger observations into a fresh Cartographer document."""
    from cartographer.core import Cartographer

    source = events.scan() if isinstance(events, EventLedger) else list(events or [])
    ledger = EventLedger(events=source)  # validates before replaying anything
    cart = Cartographer(run_dir or ".")
    cart.doc = {"target": None, "updated": 0, "nodes": {}, "log": [],
                "hypotheses": {}, "findings": [], "cleanup_obligations": []}
    current_batch, observations, ts = None, [], 0

    def flush():
        if observations:
            cart.fold(list(observations), ts=ts)

    for event in ledger.scan():
        observation = event["payload"].get("observation")
        if observation is None:
            continue
        batch = event["payload"].get("batch", event["seq"])
        if current_batch is not None and batch != current_batch:
            flush()
            observations.clear()
        current_batch, ts = batch, event["ts"]
        observations.append(observation)
    flush()
    return cart.doc


__all__ = ["EventLedger", "rebuild_from_events", "KINDS", "FILENAME"]
