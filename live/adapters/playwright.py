#!/usr/bin/env python3
"""playwright adapter — isolated browser contexts per principal, capturing API calls
and exercising JS workflows. The browser's unique contribution is the DOM: records
carry dom_diff when a browser adapter measures it. capture_config is the runner recipe
(one context per principal, storage state resolved from the vault by REF)."""
try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord


def adapt(raw, ctx=None):
    """raw: the runner-normalized capture list [{url, method, status, principal,
    context, dom_diff?}] collected from page/route events."""
    ctx = ctx or {}
    records = []
    for call in raw or []:
        url = call.get("url", "")
        if not url:
            continue
        method = call.get("method", "GET")
        route = url.split("://", 1)[-1] if "://" in url else url
        route = "/" + route.split("/", 1)[1] if "/" in route else url
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"pw:{method} {route}", "method": method,
                      "route_template": route},
            principal=call.get("principal", ctx.get("principal", "anon")),
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            control_request={"method": method, "url": url},
            dom_diff=call.get("dom_diff", {}),     # browser-only measurement
            tool={"name": "playwright", "version": "unknown",
                  "configuration": {"context": call.get("context", "")}},
            confidence="medium", reproducible=True,
            state_mutated=method in ("POST", "PUT", "PATCH", "DELETE"),
            kind="observation", confirmation_status="n_a",
        ))
    return {"records": records}


def capture_config(principals, scope, run_dir):
    """The isolated-context recipe the runner follows: one context per principal,
    storage state as a vault REF (never inlined), route capture on in-scope hosts,
    HAR export into run_dir for the mitmproxy adapter."""
    return {
        "browser": "chromium",
        "contexts": [{"principal": p, "storage_state": f"vault://{p}", "scope": scope}
                     for p in principals],
        "capture": {"routes": scope, "export": f"{run_dir}/pw-capture.har"},
    }
