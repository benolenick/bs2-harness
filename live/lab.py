#!/usr/bin/env python3
"""lab — the BS2 HTTP Laboratory (Ben 2026-08-25): "the most important addition is not
another scanner. It is a BS2 HTTP Laboratory":

    browser/proxy observation
        -> endpoint + parameters + workflow + principal
        -> controlled replay as anonymous/user/admin/other tenant
        -> status/header/JSON/DOM/timing comparison
        -> map observation or testable hypothesis
        -> independent confirmation

This module is the deterministic spine of that pipeline. Adapters produce the typed
ObservationRecord; observe() adapts raw tool output; run() folds the record into the
shared application model and replays it through the differential matrix; confirm()
closes it through the skeptic. NOTHING enters the map as confirmed except here, and
only with evidence refs + the manager's confirm lever + a surviving skeptic.
"""
from __future__ import annotations
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from observation import ObservationRecord
except ImportError:                      # live/ imported as a package
    from ..observation import ObservationRecord
import differential as DIFF
import skeptic

SQLMAP_POLICY = {
    "awaken_only_after": "a credible injection hypothesis in the map",
    "spray": "never",
    "extraction": "never by default",
}

# P0-4 (2026-08-25 re-audit): evidence refs must be TYPED receipts (telemetry seqs or
# adapter evidence locations) — an arbitrary string must never satisfy confirmation.
EVIDENCE_PREFIXES = ("har:", "oob-log:", "zap-report:", "nuclei:", "restler-bugs:",
                     "schemathesis:", "katana:", "mitm:", "pw:", "file:")


def _valid_evidence_refs(evidence):
    def ok(e):
        e = str(e)
        if re.fullmatch(r"telemetry:\d+", e):
            return True
        return any(e.startswith(p) and len(e) > len(p) for p in EVIDENCE_PREFIXES)
    return all(ok(e) for e in (evidence or []))

SQL_HINTS = ("sqli", "sql-injection", "sql injection", "blind-sqli", "boolean-based")


def injection_hypothesis_present(records):
    """The sqlmap gate: sqlmap is awakened only when a credible injection hypothesis
    already exists (a scanner lead, an error-verbosity delta). Never sprayed, never
    defaulting to extraction."""
    for r in records or []:
        rec = r.to_dict() if isinstance(r, ObservationRecord) else (r or {})
        blob = " ".join(str(rec.get(k, "")) for k in ("endpoint", "tool", "response_delta"))
        if any(h in blob.lower() for h in SQL_HINTS):
            return True
    return False


def observe(tool, raw, ctx, appmodel, vault, runner=None, ledger=None, mutations=False):
    """Stage 1 of the Laboratory: adapt raw tool output into typed records, fold the
    discovery observations into the map, then run each record through stages 2-5."""
    from adapters import adapt as adapt_tool
    out = adapt_tool(tool, raw, ctx)
    for fold in out.get("folds", []):
        appmodel.fold([fold])
    records = []
    for r in out.get("records", []):
        rec = r if isinstance(r, ObservationRecord) else ObservationRecord.from_dict(r)
        records.append(run(rec, appmodel, vault, runner=runner, ledger=ledger,
                           mutations=mutations))
    return records


def run(record, appmodel, vault, runner=None, ledger=None, mutations=False):
    """Stages 2-5 of the Laboratory for one adapter record; returns the record advanced
    through the pipeline. Fail-closed: anything that cannot complete leaves the record
    unconfirmed — never the opposite."""
    problems = record.validate()
    if problems:
        record.confirmation_status = "rejected"
        record.response_delta = {"rejected": True, "why": problems}
        return record
    # stage 2 — map: fold endpoint/principal/tenant into the shared application model
    route = record.endpoint.get("route_template", "")
    if route:
        fold = f"endpoint={record.endpoint.get('method', 'GET')} {route}"
        if record.endpoint.get("vhost"):
            fold += f" vhost={record.endpoint['vhost']}"
        appmodel.fold([fold])
    if ":" in record.principal:
        appmodel.fold([f"identity={record.principal}"])
    if record.tenant:
        appmodel.fold([f"identity=tenant:{record.tenant}"])
    map_ep = _find_endpoint(appmodel, record.endpoint)
    if map_ep is not None:
        record.map_node = map_ep["id"]
    # stages 3+4 — controlled replay across every principal, structured comparison
    if map_ep is not None and runner is not None:
        deltas = DIFF.matrix(map_ep, _session_pool(vault), runner, ledger=ledger,
                             mutations=mutations or record.state_mutated)
        d = _strongest_delta(deltas)
        if d:
            record.response_delta.update(d)
            if d.get("control_request") or d.get("test_request"):
                record.control_request = {"control": d.get("control_request"),
                                          "test": d.get("test_request")}
    # stage 5 — hypothesize: a candidate on an observation promotes it to a hypothesis
    if record.response_delta.get("candidate") and record.kind == "observation":
        record.kind = "hypothesis"
        record.confirmation_status = "unconfirmed"
    return record


def confirm(record, skeptic_answers=None, allow_confirm=False):
    """Stage 6 — independent confirmation. The manager holds the confirm lever
    (allow_confirm, a REQUEST); the lab only applies the independently-produced skeptic
    answers — the manager can never author the verifier result. FAIL-CLOSED (P0-4):
    untyped evidence refs or an incomplete skeptic checklist leave the record
    unconfirmed. Confirmation requires a candidate + typed evidence receipts + a fully
    answered checklist with no disprover; one disprover rejects the record."""
    if not allow_confirm:
        return record
    d = record.response_delta or {}
    if not d.get("candidate") or not record.evidence:
        return record
    if not _valid_evidence_refs(record.evidence):
        record.response_delta = dict(d, refused_confirm="evidence refs are not typed receipts")
        return record
    if record.kind != "finding":
        record.kind = "finding"          # only findings may ever be confirmed
    verdict = skeptic.verdict_from(skeptic_answers or {})
    if verdict.get("verdict") == "inconclusive":
        # unanswered checklist questions: fail-closed, stays unconfirmed
        record.response_delta = dict(d, held="skeptic checklist incomplete (fail-closed)",
                                     missing=verdict.get("missing"))
        return record
    if verdict["survives"]:
        record.confirmation_status = "confirmed"
        record.reproducible = True
    else:
        record.confirmation_status = "rejected"
        record.response_delta = dict(d, disproved_by=verdict["disproved_by"])
    return record


def _session_pool(vault):
    """anon baseline + every session the vault holds — the replay axis of stage 3."""
    pool = [{"principal": "anon", "kind": "anon", "refs": {}}]
    pool += sorted(vault.sessions.values(), key=lambda s: s["principal"])
    return pool


def _find_endpoint(appmodel, ep):
    for e in appmodel.endpoints.values():
        if e["method"] == str(ep.get("method", "")).upper() \
                and e["route_template"] == ep.get("route_template"):
            return e
    return None


def _strongest_delta(deltas):
    """Prefer a delta carrying a candidate (the testable hypothesis) over bare ones."""
    best = None
    for r in deltas or []:
        if r.get("skipped"):
            continue
        d = r.get("delta") or {}
        if d.get("candidate"):
            return d
        if best is None:
            best = d
    return best


__all__ = ["run", "confirm", "observe", "injection_hypothesis_present", "SQLMAP_POLICY"]
