#!/usr/bin/env python3
"""katana adapter — SPA/form crawl output (`katana -jsonl`) is pure map material:
each line becomes an endpoint observation AND an appmodel fold. Crawled == exists,
nothing more — katana can never emit a finding."""
import json
import re

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord


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
        req = e.get("request", {})
        endpoint = req.get("endpoint", "")
        method = req.get("method", "GET")
        if not endpoint:
            continue
        route = endpoint.split("://", 1)[-1] if "://" in endpoint else endpoint
        route = "/" + route.split("/", 1)[1] if "/" in route else endpoint
        params = [m for m in re.findall(r"[/?&]([^/?=&]+)=", endpoint)]
        fold = f"endpoint={method} {route}"
        if params:
            fold += f" params={','.join(dict.fromkeys(params))}"
        folds.append(fold)
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"katana:{endpoint}", "method": method, "route_template": route},
            principal=ctx.get("principal", "anon"),
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            tool={"name": "katana", "version": "unknown",
                  "configuration": {"source": req.get("source", "")}},
            confidence="medium",          # crawled = exists, nothing more
            reproducible=True,
            state_mutated=False,
            kind="observation",
            confirmation_status="n_a",
        ))
    return {"records": records, "folds": folds}
