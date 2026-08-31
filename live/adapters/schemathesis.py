#!/usr/bin/env python3
"""schemathesis adapter — OpenAPI/GraphQL property testing incl. invalid inputs and
multi-step API workflows. Gated on a spec being present in the map. The runner (not
this module) compiles schemathesis output into the normalized failure report shape."""
import json

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord


def gate(ctx):
    ctx = ctx or {}
    if not ctx.get("spec"):
        return False, "schemathesis requires an OpenAPI/GraphQL spec in the map"
    return True, "ok"


def adapt(raw, ctx=None):
    """raw: the runner-normalized report {"failures": [{endpoint, method, check,
    example}]}. Each failure is a hypothesis (lead) — confirmation is the lab's job."""
    ctx = ctx or {}
    try:
        data = json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return {"records": [], "folds": []}
    failures = data.get("failures", []) if isinstance(data, dict) else []
    records = []
    for f in failures:
        route = f.get("endpoint", "")
        check = f.get("check", "check")
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"schemathesis:{check}", "method": f.get("method", "GET"),
                      "route_template": route or "spec://"},
            principal=ctx.get("principal", "anon"),
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            response_delta={"check": check,
                            "example": str(f.get("example", ""))[:200]},
            tool={"name": "schemathesis", "version": "unknown",
                  "configuration": {"spec": str(ctx.get("spec", ""))}},
            evidence=[f"schemathesis:{check}:{route}"],
            confidence="high", reproducible=False, state_mutated=True,
            kind="hypothesis", confirmation_status="unconfirmed",
        ))
    return {"records": records}
