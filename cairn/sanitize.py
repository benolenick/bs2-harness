"""Hardened metadata projection — the content-discipline boundary.

BS2 `battle_events.payload_json` carries offensive material (command strings, evidence
bodies). The nervous system must reason over STRUCTURE / METADATA + opaque
credential/evidence REFERENCES only — never surface a raw exploit payload. Cairn's old
loader kept the full parsed object under a `"raw"` key and passed titles verbatim; that
was convention, not a boundary. This module is the enforced boundary: an ALLOWLIST DTO.

`project_event()` returns a list of SafeFact (metadata only) or [] — it can never emit a
key outside the allowlist, and it truncates/strips free-text so a title cannot smuggle a
payload into a model slice.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Optional

TITLE_MAX = 120  # a title is a label, not a transcript

# keys we will read out of a payload, per event type. Anything else is dropped.
_ALLOW = {
    "node.added": {"type", "host", "title", "node_id", "value_ref", "user", "source", "port"},
    "evidence.recorded": {"evidence_id", "content_type"},  # NOT the evidence content/body
}


def _clean(s: Any) -> str:
    """Collapse whitespace and cap length so free text can't carry a payload."""
    s = "" if s is None else str(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:TITLE_MAX]


@dataclass
class SafeFact:
    entity: str
    kind: str            # host|flag|credential|evidence|event
    content: str         # verbatim label line, metadata only
    value_ref: Optional[str] = None   # opaque reference / answer-key value (flags, creds)
    source: str = ""
    extra: dict = field(default_factory=dict)


def project_event(seq: int, event_type: str, payload: dict) -> list[SafeFact]:
    """Project ONE battle_event into zero or more metadata-only SafeFacts."""
    src = f"event:{seq}"
    if event_type == "node.added":
        node = payload.get("node", {}) or {}
        data = node.get("data", {}) or {}
        allow = _ALLOW["node.added"]
        d = {k: data.get(k) for k in allow if k in data}
        node_id = _clean(node.get("node_id") or "misc")
        host = _clean(d.get("host") or "")
        entity = host or node_id
        ntype = _clean(d.get("type") or "node")
        title = _clean(node.get("title") or "")
        if ntype == "flag" and d.get("value_ref"):
            return [SafeFact(entity, "flag", f"[flag] {title or d.get('source','')}".strip(),
                             value_ref=_clean(d["value_ref"]), source=src)]
        if ntype == "credential" and d.get("user"):
            # include the discovery provenance (metadata, credential_refs_only) — it is the
            # unique disambiguator when several creds share a host.
            prov = _clean(data.get("source") or "")
            line = f"[credential] user={_clean(d['user'])} on {host}"
            if prov:
                line += f" via {prov}"
            return [SafeFact(entity, "credential", line.strip(),
                             value_ref=_clean(d["user"]), source=src,
                             extra={"prov": prov})]
        # ordinary recon node -> a host/fact label, metadata only
        line = f"[{ntype}] {title}".strip()
        return [SafeFact(entity, "host" if host else "fact", line, source=src)]

    if event_type == "evidence.recorded":
        ev = payload.get("evidence", {}) or {}
        allow = _ALLOW["evidence.recorded"]
        d = {k: ev.get(k) for k in allow if k in ev}
        eid = _clean(d.get("evidence_id") or "ev")
        entity = eid.replace("ev-", "") or "evidence"
        ctype = _clean(d.get("content_type") or "")
        return [SafeFact(entity, "evidence", f"[evidence] {eid} ({ctype})", source=src)]

    # lifecycle/control events -> a single coarse metadata line, no payload
    return [SafeFact("__battle__", "event", f"[{event_type}] seq{seq}", source=src)]


def assert_safe(text: str) -> None:
    """Belt-and-braces: refuse obvious payload smells in anything bound for a slice/model."""
    smells = ("BEGIN RSA", "-----BEGIN", "\nPOST ", "\nGET ", "eval(", "base64,")
    for sm in smells:
        if sm in text:
            raise ValueError(f"content-discipline: refused payload-smelling text ({sm!r})")
