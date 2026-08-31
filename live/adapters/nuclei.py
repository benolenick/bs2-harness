#!/usr/bin/env python3
"""nuclei adapter — every result is a LEAD requiring confirmation, never a finding
(Ben 2026-08-25). Parses `nuclei -jsonl` lines into hypothesis records; the matched
endpoint itself folds into the map as an observation."""
import json

try:
    from observation import ObservationRecord
except ImportError:                      # live/ imported as a package
    from ..observation import ObservationRecord

SEVERITY_CONFIDENCE = {"critical": "high", "high": "high", "medium": "medium",
                       "low": "low", "info": "low", "unknown": "low"}


def _route(matched):
    path = matched.split("://", 1)[-1] if "://" in matched else matched
    return "/" + path.split("/", 1)[1] if "/" in path else matched


def adapt(raw, ctx=None):
    ctx = ctx or {}
    records, folds = [], []
    for line in (raw or "").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        matched = e.get("matched-at", "")
        route = _route(matched) if matched else "template://"
        info = e.get("info", {})
        severity = str(info.get("severity") or "unknown").lower()
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"nuclei:{e.get('template-id', '?')}",
                      "method": "ANY", "route_template": route,
                      "vhost": ctx.get("vhost", "")},
            principal=ctx.get("principal", "anon"),
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            tool={"name": "nuclei",
                  "version": e.get("nuclei-version", "unknown"),
                  "configuration": {"template": e.get("template-id"),
                                    "matcher": e.get("matcher-name", "")}},
            evidence=[f"nuclei:{e.get('template-id', '?')}"],
            confidence=SEVERITY_CONFIDENCE.get(severity, "low"),
            reproducible=False,
            state_mutated=bool(e.get("interaction")),   # an OOB interaction is a state effect
            kind="hypothesis",
            confirmation_status="unconfirmed",          # the lead-not-finding policy
        ))
        if matched:
            folds.append(f"endpoint=ANY {route} vhost={ctx.get('vhost', '') or 'unknown'}")
    return {"records": records, "folds": folds}
