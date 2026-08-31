#!/usr/bin/env python3
"""restler adapter — stateful API fuzzer that learns producer/consumer dependencies
(banking value). EXPLICITLY GATED: requires a spec in the map, mutation_policy=
write_approved, and aggressive fuzzing never runs without an unlock."""
import json

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord


def gate(ctx):
    ctx = ctx or {}
    if not ctx.get("spec"):
        return False, "restler requires an OpenAPI/GraphQL spec in the map"
    if ctx.get("aggressive") and not ctx.get("unlock"):
        return False, "aggressive fuzzing gated: requires explicit mutation unlock"
    if ctx.get("mutation_policy") != "write_approved":
        return False, "restler requires mutation_policy=write_approved"
    return True, "ok"


def adapt(raw, ctx=None):
    """Parses restler_bugs.json — every bug bucket becomes a hypothesis (lead)."""
    ctx = ctx or {}
    try:
        data = json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return {"records": [], "folds": []}
    bugs = data.get("bugs", []) if isinstance(data, dict) else []
    records = []
    for b in bugs:
        btype = str(b.get("bug_type") or b.get("type") or "unknown")
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"restler:{btype}", "method": "ANY", "route_template": "spec://"},
            principal=ctx.get("principal", "anon"),
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            response_delta={"restler_bug": btype,
                            "reproducible": bool(b.get("reproducible"))},
            tool={"name": "restler", "version": "unknown",
                  "configuration": {"spec": str(ctx.get("spec", ""))}},
            evidence=[f"restler-bugs:{btype}"],
            confidence="medium", reproducible=bool(b.get("reproducible", False)),
            state_mutated=True,
            kind="hypothesis", confirmation_status="unconfirmed",
        ))
    return {"records": records}
