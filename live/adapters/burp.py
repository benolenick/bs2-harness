#!/usr/bin/env python3
"""burp adapter — the Montoya extension is a SCHEMA EMITTER (Java-side, not Python):
it serializes typed records per burp_schema.json, and this side ingests them verbatim.
The schema IS the wire contract between Burp-land and the Laboratory; nothing here
writes Burp code. Invalid external records fail closed (dropped, never guessed)."""
import json
import os

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "burp_schema.json")


def adapt(raw, ctx=None):
    text = (raw or "").strip()
    if not text:
        return {"records": [], "folds": []}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"records": [], "folds": []}
    if isinstance(payload, dict):
        payload = payload.get("records", [payload])
    records = []
    for r in payload or []:
        rec = ObservationRecord.from_dict(r)
        if not rec.validate():
            records.append(rec)
    return {"records": records, "folds": []}
