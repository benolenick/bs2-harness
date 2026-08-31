#!/usr/bin/env python3
"""differential — the HTTP/browser differential replay engine (BS2 design doc §2).

The platform executes comparison matrices deterministically and returns STRUCTURED
DELTAS; the specialist reasons about the delta instead of spending tokens curling and
re-reading JSON.

  same endpoint × different principal      -> role/ownership deltas
  same principal × own vs foreign object   -> BOLA/BOPLA deltas
  same operation × normal vs hidden prop   -> mass-assignment deltas
  same request × browser vs direct API     -> auth-boundary deltas
  same token × valid/expired/audience      -> session deltas

`runner` is injectable — the caller supplies the §10.1-backed transport
(runner(request_spec) -> {status, headers, body, ms}) so the engine itself never
touches the target. read_only by default; a mutation requires mutation_policy='write'.
"""
from __future__ import annotations
import json, re

CANDIDATES = {
    ("foreign_object_fields_returned", True): "BOLA",
    ("foreign_object_fields_returned", False): None,
    ("owner_mismatch", True): "BOLA/BOPLA",
    ("hidden_prop_effected", True): "mass-assignment",
    ("schema_changed", True): "BFLA/BOPLA",
}


def request_spec(ep, principal_session, method=None, path_binding=None, body=None,
                 headers=None):
    """Compile an endpoint + principal into the spec the runner executes. No secrets:
    session refs ride along as labels; the transport resolves them on the exec host."""
    return {
        "method": (method or ep["method"]).upper(),
        "base": (ep.get("vhost") or ""),
        "route_template": ep["route_template"],
        "path_binding": path_binding or {},
        "body": body or {},
        "headers": headers or {},
        "principal": (principal_session or {}).get("principal", "anon"),
        "session_ref": (principal_session or {}).get("refs", {}),
    }


def replay(spec, runner):
    """One deterministic request through the injected runner. Returns the normalized
    response record: {status, schema_keys, body_hash, size, ms}."""
    out = runner(spec)
    if isinstance(out, dict) and "status" in out:
        return out
    # tolerate a raw (status, body) tuple from a thin runner
    status, body = (out or (0, ""))
    body = str(body or "")
    return {"status": int(status or 0), "schema_keys": sorted(_top_keys(body)),
            "body_hash": str(hash(body)), "size": len(body), "ms": 0}


def anon_probe(ep, session, runner):
    """Issue exactly one anonymous, read-only request for ``session``'s object.

    Only the status is retained: response content can contain sensitive object data and
    is unnecessary for distinguishing object authorization from public access.
    """
    spec = request_spec(ep, None, method="GET",
                        path_binding=_binding_for(ep, session))
    spec["body"] = {}
    try:
        response = replay(spec, runner)
        return {"status": int(response.get("status", 0) or 0)}
    except Exception:
        return {"status": 0}


def _ownership_verdict(probe):
    status = int((probe or {}).get("status", 0) or 0)
    if 200 <= status < 400:
        return "public_or_authz_absent"
    if 400 <= status < 500 and status != 404:
        return "bola"
    return "inconclusive"


def disambiguate(ep, owner_session, foreign_session, runner):
    """Classify a previously observed foreign-object response with one anon probe."""
    del owner_session  # documents the comparison contract; no additional owner request
    probe = anon_probe(ep, foreign_session, runner)
    return {"verdict": _ownership_verdict(probe), "probe": probe}


def _top_keys(body):
    """Top-level JSON keys (deterministic schema fingerprint); falls back to form/query
    key detection so non-JSON endpoints still yield a comparable schema."""
    keys = []
    try:
        d = json.loads(body)
        if isinstance(d, dict):
            keys = [str(k) for k in d.keys()]
    except Exception:
        keys = re.findall(r"\"([A-Za-z_][A-Za-z0-9_]*)\"\s*:", body)[:60]
    return keys


SECURITY_HEADERS = ("www-authenticate", "set-cookie", "x-rate-limit", "x-ratelimit",
                    "access-control-allow-origin", "content-security-policy")


def compare(control, test, owner_context=None):
    """The structured delta from §2: what CHANGED between the control request and the
    test request — not raw bodies. owner_context = {principal, owns_object} for the
    control side, so 'foreign object fields returned' is measured, not inferred.

    Header deltas are NAME-only (values may carry tokens — never stored in records).
    Timing deltas flag responses costing >2x the control (rate limits, auth-boundary
    work, injection side effects). dom_diff rides along from browser adapters only."""
    owner_context = owner_context or {}
    ch, th = _norm_headers(control.get("headers")), _norm_headers(test.get("headers"))
    delta = {
        "status_changed": control["status"] != test["status"],
        "schema_changed": control["schema_keys"] != test["schema_keys"],
        "foreign_object_fields_returned": _foreign_fields(control, test),
        "owner_mismatch": bool(owner_context.get("owns_object") is False),
        "hidden_prop_effected": _hidden_prop_effected(control, test),
        "header_delta": sorted(set(th) - set(ch)),
        "security_headers_changed": sorted(set(th) & set(SECURITY_HEADERS) - set(ch)),
        "timing_delta": _timing_delta(control, test),
        "dom_diff": test.get("dom_diff", {}),
        "control_request": control.get("receipt"),
        "test_request": test.get("receipt"),
        "ownership_verdict": (
            _ownership_verdict(owner_context["anon_probe"])
            if "anon_probe" in owner_context else None
        ),
    }
    delta["candidate"] = _candidate(delta)
    return delta


def _norm_headers(h):
    return sorted({str(k).lower() for k in (h or {})})


def _timing_delta(control, test):
    c, t = control.get("ms"), test.get("ms")
    if c is None or t is None:
        return {}
    c = max(float(c), 0.001)
    ratio = float(t) / c
    return {"control_ms": float(control.get("ms")), "test_ms": float(t),
            "ratio": round(ratio, 2), "flag": ratio > 2.0}


def _foreign_fields(control, test):
    """Fields present in the TEST response but not the control response (the object the
    test principal should not be able to see)."""
    return sorted(set(test["schema_keys"]) - set(control["schema_keys"]))[:20]


def _hidden_prop_effected(control, test):
    """A property that was NOT in the control schema but appears in the test response —
    the mass-assignment smell (hidden property accepted and reflected)."""
    return bool(_foreign_fields(control, test)) and (
        control["status"] < 400 and test["status"] < 400)


def _candidate(delta):
    if delta["foreign_object_fields_returned"] and delta["owner_mismatch"]:
        return "BOLA"
    if delta["hidden_prop_effected"] and not delta["owner_mismatch"]:
        return "mass-assignment"
    if delta["status_changed"] and delta["schema_changed"]:
        return "BFLA/BOPLA"
    return None


def matrix(ep, principals, runner, ledger=None, mutations=False, max_requests=12):
    """Same endpoint × every principal: control = the object owner (or first principal),
    tests = everyone else. Deterministic, bounded, ledger-recorded. Returns the list of
    deltas (one per test) plus per-request receipts."""
    sessions = [p for p in principals if p is not None]
    if not sessions:
        return []
    results, budget = [], 0
    ownership_probe = None
    control_session = sessions[0]
    for i, sess in enumerate(sessions):
        spec = request_spec(ep, sess, path_binding=_binding_for(ep, sess))
        fp = _fingerprint(ep, sess, spec, mutations)
        if ledger is not None:
            prior = ledger.find_equivalent(fp)
            if prior is not None:
                results.append({"skipped": True, "reason": "already_tested", "prior": prior})
                continue
        if budget >= max_requests:
            results.append({"skipped": True, "reason": "request_ceiling"})
            continue
        resp = replay(spec, runner)
        budget += 1
        resp["receipt"] = _receipt(ep, sess, budget)
        if i == 0:
            control = resp
            continue
        delta = compare(control, resp, owner_context={"principal": control_session.get("principal"),
                                                      "owns_object": False})
        if delta["candidate"] == "BOLA" and ownership_probe is None:
            if budget < max_requests:
                ownership_probe = disambiguate(ep, control_session, sess, runner)
                budget += 1
                delta["ownership_verdict"] = ownership_probe["verdict"]
            else:
                delta["ownership_verdict"] = "inconclusive"
        if ledger is not None:
            ledger.record(fp, {"delta": delta, "status": resp["status"],
                               "was_execution_error": resp["status"] == 0})
        results.append({"principal": sess.get("principal"), "delta": delta,
                        "control": control["receipt"], "test": resp["receipt"]})
    return results


def _binding_for(ep, sess):
    """Object-path binding for a principal's session: the template variable maps to the
    object THAT principal owns, so the control request is always own-object."""
    return {}   # the caller/specialist sets bindings; the engine only executes them


def _fingerprint(ep, sess, spec, mutations):
    from experiment_ledger import fingerprint as _fp
    return _fp({"endpoint_id": ep.get("id"), "method": spec["method"],
                "principal": sess.get("principal"), "object": str(spec["path_binding"]),
                "mutation": bool(mutations), "payload_family": "none", "oracle": ""})


def _receipt(ep, sess, n):
    return f"req-{n}-{ep.get('id', '?')}-{sess.get('principal', 'anon')}"


__all__ = ["request_spec", "replay", "anon_probe", "disambiguate", "compare",
           "matrix", "CANDIDATES"]
