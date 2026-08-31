#!/usr/bin/env python3
"""mitmproxy adapter — captured flows (HAR) become (control, modified) replay pairs:
the exact control request rides in the record, and the replay stage fills the modified
half. Header VALUES are never stored — tokens live in the session vault, so the record
carries header NAMES and body hashes only."""
import hashlib
import json

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord

MUTATING = ("POST", "PUT", "PATCH", "DELETE")


def _hash(b):
    return hashlib.sha256(str(b).encode()).hexdigest()[:16] if b else ""


def adapt(raw, ctx=None):
    ctx = ctx or {}
    try:
        har = json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return {"records": [], "folds": []}
    records = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url", "")
        method = req.get("method", "GET")
        if not url:
            continue
        hdr_names = sorted({str(h.get("name", "")).lower()
                            for h in req.get("headers", [])} - {""})
        body = (req.get("postData") or {}).get("text", "")
        resp = entry.get("response", {})
        rbody = (resp.get("content") or {}).get("text", "")
        route = url.split("://", 1)[-1] if "://" in url else url
        route = "/" + route.split("/", 1)[1] if "/" in route else url
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"mitm:{method} {route}", "method": method,
                      "route_template": route},
            principal=ctx.get("principal", "anon"),
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            control_request={"method": method, "url": url,
                             "header_names": hdr_names, "body_hash": _hash(body)},
            modified_request={},       # filled by the replay stage when the request is altered
            tool={"name": "mitmproxy", "version": "unknown",
                  "configuration": {"format": "har"}},
            evidence=[f"har:{route}:{_hash(body + rbody)}"],
            confidence="medium", reproducible=True,
            state_mutated=method in MUTATING,
            kind="observation", confirmation_status="n_a",
        ))
    return {"records": records}
