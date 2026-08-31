#!/usr/bin/env python3
"""bola_slice — the P1-2 vertical-slice CORE as a library (2026-08-25).

Extracted from scripts/lab_slice.py so consumers (run_deep_deepseek's BOLA lane, the
manager loop) can drive the SAME deterministic matrix the CLI proves:

    isolated principal sessions -> own-object ids via the app's OWN list endpoint
    -> differential matrix (control=owner x own object, test=foreign x that object)
    -> one BOUND anon probe on the SAME object (ownership-diff)
    -> anon gated + foreign authed 200 = BOLA candidate (even on identical schema —
       the schema-diff oracle alone cannot see same-schema exposure)
    -> skeptic-gated confirmation from records (observe once, confirm from records).

The plan describes the engagement GENERICALLY (endpoints, principals-as-REFS, id
sources). This module knows no app. Every request rides the injected runner — the
caller supplies the governed transport (governed_runner.make_runner) so no path here
ever touches a target directly.
"""
from __future__ import annotations
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in __import__("sys").path:
    __import__("sys").path.insert(0, HERE)

import differential as DIFF            # noqa: E402
import lab                              # noqa: E402
import skeptic                          # noqa: E402
from observation import ObservationRecord   # noqa: E402
from experiment_ledger import ExperimentLedger  # noqa: E402


def load_plan(path):
    plan = json.load(open(path))
    assert plan.get("target") and plan.get("endpoints") and plan.get("principals"), \
        "plan needs target + endpoints + principals"
    return plan


def _auth_headers(principal):
    """principal's auth refs -> transport headers. A token_file ref is read from the
    600 file on this host and rides ONLY in the governed curl command (the door audits
    cmd_sha, not values). Header values are never printed, logged, or recorded."""
    headers = {}
    token_file = (principal.get("auth") or {}).get("token_file") or ""
    if token_file and os.path.isfile(token_file):
        with open(token_file) as fh:
            token = fh.read().strip()
        if not token.lower().startswith("bearer "):   # idempotent: either file format
            token = "Bearer " + token
        headers["Authorization"] = token
    return headers


def collect_object_ids(plan, principal, runner):
    """Fetch each principal's OWN object ids via the plan's id_sources (the list
    endpoints the app itself exposes), using that principal's session."""
    ids = {}
    for var, src in (plan.get("id_sources") or {}).items():
        spec = {"method": src.get("method", "GET"),
                "base": plan["target"],
                "route_template": src["route_template"],
                "headers": _auth_headers(principal),
                "session_ref": principal.get("refs") or {},
                "principal": principal["principal"]}
        rec = runner(spec)
        try:
            data = json.loads(rec.get("body") or "{}")
        except Exception:
            data = {}
        # crAPI-style list shapes: {"vehicles": [...]} or a bare list
        items = data if isinstance(data, list) else (data.get(src.get("list_field", "")) or [])
        vals = [str(it.get(src["field"])) for it in items if isinstance(it, dict)
                and it.get(src["field"])]
        ids[var] = vals
    return ids


def _anon_probe(plan, ep, var, own_first, runner):
    """One anonymous, READ-ONLY request for the SAME bound object (the matrix helper's
    _binding_for is an unbound stub — bind here). Only the status is retained."""
    anon_ep = {**ep, "vhost": plan["target"]}
    anon_spec = DIFF.request_spec(anon_ep, None, method="GET",
                                  path_binding={var: own_first})
    return {"status": runner(anon_spec).get("status", 0)}


def run_slice(plan, runner, ledger_dir=None, skeptic_answers=None, plan_name=""):
    """Drive the full matrix over the plan. Returns
    {"findings": [ObservationRecord, ...], "briefs": [str, ...], "rows": [status str, ...],
     "object_ids": {principal: {var: [ids]}}}.

    ledger_dir: no-repeat ledger directory (str/path -> loaded if present, SAVED after
    the run; an ExperimentLedger instance -> shared in-process ledger; None = no dedup).
    skeptic_answers: full checklist dict -> records are CONFIRMED in place
    (fail-closed: partial answers hold unconfirmed, never confirmed)."""
    if ledger_dir is None:
        ledger = None
    elif hasattr(ledger_dir, "should_retest"):
        ledger = ledger_dir
    else:
        ledger = ExperimentLedger.open(ledger_dir)
    object_ids = {p["principal"]: collect_object_ids(plan, p, runner)
                  for p in plan["principals"]}
    findings, briefs, rows = [], [], []
    for ep in plan["endpoints"]:
        var = ep["template_var"]
        for control_p in plan["principals"]:
            own = object_ids[control_p["principal"]].get(var, [])
            if not own:
                continue
            for test_p in plan["principals"]:
                if test_p is control_p:
                    continue
                # control = owner's own object; test = foreign principal x owner's object
                ctrl_spec = {"method": ep["method"], "base": plan["target"],
                             "route_template": ep["route_template"],
                             "path_binding": {var: own[0]},
                             "headers": _auth_headers(control_p),
                             "session_ref": control_p.get("refs") or {},
                             "principal": control_p["principal"]}
                test_spec = {**ctrl_spec, "headers": _auth_headers(test_p),
                             "session_ref": test_p.get("refs") or {},
                             "principal": test_p["principal"]}
                fp = f"{ep['id']}|{control_p['principal']}|{test_p['principal']}"
                if ledger is not None:
                    ok_retest, why = ledger.should_retest(
                        fp, current_version=1, learns_anything_new=True)
                    if not ok_retest:
                        rows.append(f"[slice] {fp}: already tested, skip ({why})")
                        continue
                ctrl, test = runner(ctrl_spec), runner(test_spec)
                ctrl["receipt"], test["receipt"] = f"req-c-{fp}", f"req-t-{fp}"
                delta = DIFF.compare(ctrl, test, owner_context={
                    "principal": control_p["principal"], "owns_object": False})
                # an explicit refusal on the foreign request is authz WORKING — a
                # genuine negative, not a candidate (200-with-foreign-data is the only
                # BOLA evidence)
                if delta.get("candidate") and test["status"] in (401, 403):
                    delta["candidate"] = None
                verdict = DIFF._ownership_verdict(_anon_probe(plan, ep, var, own[0], runner))
                if test["status"] == 200 and verdict == "bola" \
                        and not delta.get("candidate"):
                    delta["candidate"] = "BOLA"
                delta["ownership_verdict"] = verdict
                if ledger is not None:
                    ledger.record(fp, {"delta": delta,
                                       "was_execution_error": ctrl["status"] == 0,
                                       # map_version anchors 'map_changed_since': without
                                       # it the ledger sees None and retests forever
                                       "map_version": 1})
                rows.append(f"[slice] {fp}: control={ctrl['status']} test={test['status']} "
                            f"candidate={delta['candidate']} verdict={delta['ownership_verdict']} "
                            f"foreign={delta['foreign_object_fields_returned']}")
                if not delta.get("candidate"):
                    continue
                rec = ObservationRecord(
                    target=plan["target"],
                    endpoint={"id": ep["id"], "method": ep["method"],
                              "route_template": ep["route_template"]},
                    principal=test_p["principal"], tenant=control_p.get("tenant", ""),
                    map_node=ep["id"], control_request={"control": ctrl["receipt"]},
                    modified_request={"test": test["receipt"]},
                    response_delta=delta,
                    tool={"name": "lab-slice", "version": "1",
                          "configuration": {"plan": os.path.basename(plan_name)
                                            or "inline"}},
                    evidence=[f"telemetry:{ledger.stats().get('experiments', 0)}"
                              if ledger else f"telemetry:{len(rows)}"],
                    confidence="medium", state_mutated=ep["method"] != "GET",
                )
                if skeptic_answers is not None:
                    rec = lab.confirm(rec, skeptic_answers=skeptic_answers,
                                      allow_confirm=True)
                briefs.append(skeptic.build_brief({
                    "claim": f"{delta['candidate']} on {ep['route_template']}",
                    "impact": "high" if delta["foreign_object_fields_returned"]
                              else "medium",
                    "delta": delta, "state": fp, "evidence_refs": rec.evidence}))
                findings.append(rec)
    if ledger is not None and getattr(ledger, "run_dir", None):
        ledger.save()
    return {"findings": findings, "briefs": briefs, "rows": rows,
            "object_ids": object_ids}


def confirm_records(records, skeptic_answers):
    """Observe-once discipline: confirmation runs off the COLLECTED records, no new
    target requests. Fail-closed — partial answers hold unconfirmed."""
    out = []
    for rec in records:
        out.append(lab.confirm(rec, skeptic_answers=skeptic_answers, allow_confirm=True))
    return out


__all__ = ["load_plan", "collect_object_ids", "run_slice", "confirm_records"]
