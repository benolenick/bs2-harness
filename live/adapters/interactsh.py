#!/usr/bin/env python3
"""interactsh adapter — SELF-HOSTED ONLY (bank traffic never goes to a public callback
service). Parses the local interactsh log (JSONL: host/timestamp/request-type/...) into
out-of-band hypothesis records; evidence = local log line refs."""
import json

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord

PUBLIC_CALLBACK_DOMAINS = {
    "oast.fun", "oast.me", "oast.live", "oast.site", "oast.online",
    "oast.pro", "oastify.com", "interact.sh", "burpcollaborator.net",
}


def assert_self_hosted(domain):
    """Fail-closed: a public callback domain is never accepted."""
    return not any(domain.endswith(d) for d in PUBLIC_CALLBACK_DOMAINS)


def adapt(raw, ctx=None):
    ctx = ctx or {}
    domain = ctx.get("callback_domain", "")
    if domain and not assert_self_hosted(domain):
        raise ValueError(f"refusing public callback domain {domain!r}: self-hosted only")
    records = []
    for line in (raw or "").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = e.get("host", "")
        if not host:
            continue
        records.append(ObservationRecord(
            target=ctx.get("target", ""),
            endpoint={"id": f"oob:{host}", "method": "OOB", "route_template": host},
            principal="anon",
            tenant=ctx.get("tenant", ""),
            map_node=ctx.get("map_node", "unmapped"),
            response_delta={"out_of_band": True,
                            "request_type": e.get("request-type", "")},
            tool={"name": "interactsh", "version": "unknown",
                  "configuration": {"domain": domain or "self-hosted"}},
            evidence=[f"oob-log:{host}:{e.get('timestamp', '')}"],
            confidence="high" if e.get("request-type") in ("http", "dns") else "medium",
            reproducible=False, state_mutated=False,
            kind="hypothesis", confirmation_status="unconfirmed",
        ))
    return {"records": records}
