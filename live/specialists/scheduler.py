#!/usr/bin/env python3
"""scheduler — event-driven wake/sleep, the scheduling score, typed proposal
compilation, the escalation ladder, and the operator cost preview (BS2 doc §3/§8/§10).

A specialist WAKES only when evidence makes it relevant: its triggers appear in the
shared application model AND its requires are satisfied by the model + session vault.
It performs ONE bounded investigation (compiled into typed experiments, executed by
the shared replay engine) and then SLEEPS until a wake_again_on event changes its
preconditions. It does not run merely because it is enabled.

Scheduling score (higher = run sooner):

    expected_information_gain × likely_impact × evidence_confidence × route_relevance
    ---------------------------------------------------------------------------------
                        tokens × requests × intrusiveness

The score prefers a six-request authorization comparison over a speculative 20-minute
specialist session.

Escalation ladder (§8): deterministic parsers/comparators first, then replay
primitives, then cheap LLM, then strong LLM, then Opus for ambiguous high-value
reasoning, then a human for intrusive or business-sensitive testing. This module
builds the deterministic tiers; LLM tiers are selected BY pick_tier and handed to the
caller (the manager loop) as recommendations.
"""
from __future__ import annotations
import json, re
from observation import ObservationRecord

# ---- map-level trigger vocabulary ------------------------------------------------
TRIGGER_CHECKS = {
    "object_identifier_present":  lambda am, v: bool(am.templated_endpoints()),
    "authenticated_endpoint":     lambda am, v: any(ep.get("auth_state") not in ("", "unknown", "anon")
                                                   for ep in am.endpoints.values()),
    "session_boundary_observed":  lambda am, v: bool(v.sessions),
    "workflow_present":           lambda am, v: bool(am.workflows),
    "state_changing_endpoint":    lambda am, v: any(ep.get("method") in ("POST", "PUT", "PATCH", "DELETE")
                                                   for ep in am.endpoints.values()),
}

REQUIRE_CHECKS = {
    "two_distinct_principals":       lambda am, v: len([p for p in v.sessions.values()
                                                        if p["kind"] in ("user", "privileged", "tenant")]) >= 2,
    "one_owned_object_per_principal": lambda am, v: len({o.get("owner") for o in am.objects.values()
                                                        if o.get("owner")}) >= 2,
    "two_session_states":            lambda am, v: len({s["kind"] for s in v.sessions.values()
                                                       if s["kind"] in ("mfa_partial", "mfa_complete")}) >= 2,
    "workflow_transition":           lambda am, v: any(w.get("transitions") for w in am.workflows.values()),
    "repeatable_control":            lambda am, v: any(ep.get("method") == "GET"
                                                      for ep in am.endpoints.values()),
}

# intrusiveness factors (read_only = 1; mutation = 10; concurrency = 8)
INTRUSIVENESS = {"read_only": 1, "write_approved": 10}

TIERS = ["deterministic", "replay", "cheap_llm", "strong_llm", "opus", "human"]


def pick_tier(needs_interpretation, ambiguity, intrusive, impact):
    """§8 escalation ladder: spend model context only where reasoning is actually
    required. Deterministic comparisons never pay for an LLM; intrusive or
    business-sensitive tests escalate to a human decision."""
    if intrusive:
        return "human"
    if ambiguity and impact in ("critical", "high"):
        return "opus"
    if needs_interpretation:
        return "strong_llm" if impact in ("critical", "high") else "cheap_llm"
    return "deterministic"


class Scheduler:
    def __init__(self, appmodel, vault, specialists, ledger=None):
        self.am = appmodel
        self.vault = vault
        self.specs = {s["id"]: s for s in specialists.values()}
        self.ledger = ledger
        self.events = []        # map events observed since boot (wake_again_on keys)
        self.records = []       # latest normalized adapter-record feed; never executed here

    # ---- wake / sleep ------------------------------------------------------------
    def emit_event(self, name):
        self.events.append(name)

    def feed(self, records):
        """Replace the latest adapter feed with valid typed records. No proposal fires."""
        latest = []
        for value in records or []:
            record = value if isinstance(value, ObservationRecord) \
                else ObservationRecord.from_dict(value) if isinstance(value, dict) else None
            if record is not None and not record.validate():
                latest.append(record)
        self.records = latest
        return len(latest)

    @staticmethod
    def _record_id(record):
        return (record.response_delta.get("record_id") or record.map_node
                or record.endpoint.get("id") or "unmapped")

    def _record_wake_reason(self, spec_id):
        candidates = {"BOLA", "BOPLA", "mass-assignment", "BFLA/BOPLA"}
        for record in self.records:
            rid = self._record_id(record)
            delta = record.response_delta or {}
            if spec_id == "authorization" and delta.get("candidate") in candidates:
                return f"record {rid} candidate={delta['candidate']}"
            if spec_id == "identity-session":
                delta_text = json.dumps(delta, sort_keys=True, default=str).lower()
                route = str(record.endpoint.get("route_template", "")).lower()
                if (any(word in delta_text for word in ("session", "token", "stale", "replay"))
                        or any(word in route for word in
                               ("session", "token", "login", "logout", "refresh", "mfa"))):
                    return f"record {rid} carries an identity/session signal"
            if spec_id == "workflow-state":
                endpoint_ids = {str(record.map_node), str(record.endpoint.get("id", ""))}
                for workflow in self.am.workflows.values():
                    if any(str(t.get("via", "")) in endpoint_ids
                           for t in workflow.get("transitions", [])):
                        return f"record {rid} is tied to workflow {workflow.get('id', '?')}"
        return ""

    def _triggers_hold(self, spec):
        return any(TRIGGER_CHECKS.get(t, lambda am, v: False)(self.am, self.vault)
                   for t in spec.get("triggers", []))

    def _requires_hold(self, spec):
        return all(REQUIRE_CHECKS.get(r, lambda am, v: False)(self.am, self.vault)
                   for r in spec.get("requires", []))

    def status(self, spec_id):
        """awake | asleep(trigger) | asleep(requires) | asleep(event) — with the reason,
        so the operator sees WHY each specialist is awake or asleep (§10)."""
        spec = self.specs[spec_id]
        record_reason = self._record_wake_reason(spec_id)
        if record_reason:
            return ("awake", record_reason)
        if not self._triggers_hold(spec):
            return ("asleep", f"no trigger among {','.join(spec['triggers'])} in the map")
        if not self._requires_hold(spec):
            return ("asleep", f"requires unmet: {spec['requires']}")
        return ("awake", "")

    def awake_specialists(self):
        return [sid for sid in self.specs if self.status(sid)[0] == "awake"]

    # ---- the scheduling score ------------------------------------------------------
    def score(self, spec_id):
        """info_gain × impact × confidence × relevance ÷ (tokens × requests × intrusiveness).
        Deterministic estimates: information gain = number of fresh experiments the
        proposal compiler yields; confidence/impact/relevance come from the contract and
        the map (route relevance = how many templated/workflow surfaces match)."""
        spec = self.specs[spec_id]
        proposals = self.propose(spec_id)
        info_gain = len(proposals) or 0.5
        impact = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}.get(
            spec.get("impact", "medium"), 2.0)
        confidence = 1.0   # map facts are typed evidence, not prose
        relevance = 1.0 + 0.5 * len(proposals)
        tokens = spec["max_tokens"] / 1000.0
        requests = spec["max_requests"]
        intrusiveness = INTRUSIVENESS.get(spec.get("mutation_policy"), 1)
        if info_gain <= 0 or requests <= 0:
            return 0.0
        return round(info_gain * impact * confidence * relevance /
                     (tokens * requests * intrusiveness), 4)

    def ranked(self):
        return sorted(((sid, self.score(sid)) for sid in self.awake_specialists()),
                      key=lambda x: -x[1])

    # ---- typed proposal compilation (§4: output is an experiment, not a command) ----
    def propose(self, spec_id):
        spec = self.specs[spec_id]
        if self.status(spec_id)[0] != "awake":
            return []
        fn = {"authorization": self._propose_authorization,
              "identity-session": self._propose_identity_session,
              "workflow-state": self._propose_workflow_state}.get(spec_id)
        if fn is None:
            return []
        props = fn(spec)
        # the no-repeat ledger prunes already-run equivalents at proposal time (§5)
        if self.ledger is not None:
            props = [p for p in props
                     if self.ledger.find_equivalent(_fp_of(p, spec)) is None]
        return props[: spec["max_requests"]]

    def _propose_authorization(self, spec):
        """For each {id} endpoint whose object type is on the map: control = each
        principal's OWN object, test = the OTHER principal's object. The delta between
        those two responses is the BOLA/BOPLA oracle input."""
        props = []
        eps = [e for e in self.am.templated_endpoints() if e.get("object_type")]
        users = [p for p in self.am.distinct_principals()
                 if p["kind"] in ("user", "privileged", "tenant")]
        if len(users) < 2:
            return []
        for ep in eps:
            objs = self.am.objects_for(otype=ep["object_type"])
            owners = {o["owner"] for o in objs if o.get("owner")}
            if len(owners) < 2:
                continue
            by_owner = {}
            for o in objs:
                by_owner.setdefault(o["owner"], o)
            for i, principal in enumerate(users):
                own = by_owner.get(principal["id"])
                foreign = next((o for o in objs if o.get("owner") and o["owner"] != principal["id"]), None)
                if not own or not foreign:
                    continue
                var = re.search(r"\{([^}]+)\}", ep["route_template"])
                var = var.group(1) if var else "id"
                props.append({
                    "endpoint_id": ep["id"],
                    "principal": principal["id"],
                    "object_binding": f"{foreign['owner']}:{foreign['oid']}",
                    "control_binding": {var: own["oid"]},
                    "change": {"path_parameter": foreign["oid"]},
                    "oracle": "foreign_object_returned",
                    "request_ceiling": 2,
                })
        return props

    def _propose_identity_session(self, spec):
        """Session-state matrix: same request through mfa-complete vs mfa-incomplete
        sessions; acceptance mismatch is the oracle."""
        props = []
        half = self.vault.sessions_for_kind("mfa_partial")
        full = self.vault.sessions_for_kind("mfa_complete")
        eps = [e for e in self.am.endpoints.values() if e.get("auth_state") not in ("", "unknown")]
        for ep in eps[:4]:
            for h, f in zip(half[:1], full[:1]):
                props.append({
                    "endpoint_id": ep["id"],
                    "principal": f["principal"],
                    "object_binding": "",
                    "change": {"session_state": h["kind"]},
                    "oracle": "session_acceptance_mismatch",
                    "request_ceiling": 2,
                })
        return props

    def _propose_workflow_state(self, spec):
        """State-machine invariants: for each workflow transition, propose skip-state
        (jump over a state) and replay (repeat a transition) read-only tests."""
        props = []
        for w in self.am.workflows.values():
            states, trs = w.get("states", []), w.get("transitions", [])
            if len(states) < 3 or not trs:
                continue
            via = next((t["via"] for t in trs if t.get("via")), "")
            ep = self.am.endpoints.get(via)
            if ep is None:
                continue
            props.append({
                "endpoint_id": ep["id"],
                "principal": "anon",
                "object_binding": "",
                "change": {"skip_state": f"{trs[0]['from']}->{trs[-1]['to']}"},
                "oracle": "state_skipped",
                "request_ceiling": 2,
            })
            props.append({
                "endpoint_id": ep["id"],
                "principal": "anon",
                "object_binding": "",
                "change": {"replay_transition": f"{trs[0]['from']}->{trs[0]['to']}"},
                "oracle": "replay_accepted",
                "request_ceiling": 2,
            })
        return props

    # ---- cost preview (§10) ---------------------------------------------------------
    def preview(self):
        rows = []
        for sid in self.specs:
            state, why = self.status(sid)
            spec = self.specs[sid]
            n = len(self.propose(sid)) if state == "awake" else 0
            rows.append({
                "id": sid, "state": state, "why": why,
                "requests": n * 2 if state == "awake" else 0,
                "model_turns": 0 if not n else max(1, n // 3),
                "minutes": spec["max_minutes"] if state == "awake" else 0,
                "mutation": spec["mutation_policy"],
                "intrusive": spec["mutation_policy"] != "read_only",
            })
        tot_req = sum(r["requests"] for r in rows)
        tot_turns = sum(r["model_turns"] for r in rows)
        tot_min = sum(r["minutes"] for r in rows)
        awake = [r for r in rows if r["state"] == "awake"]
        return {
            "detected": f"{len(awake)}/{len(self.specs)} specialists applicable",
            "records": len(self.records),
            "awake_reasons": {r["id"]: r["why"] for r in awake if r["why"]},
            "rows": rows,
            "estimates": {"requests": tot_req, "model_turns": tot_turns,
                          "minutes": tot_min},
            "intrusive_blocked": [r["id"] for r in rows if r["intrusive"]],
        }


def _fp_of(proposal, spec):
    from experiment_ledger import fingerprint
    return fingerprint({
        "endpoint_id": proposal.get("endpoint_id", ""),
        "method": "GET",
        "principal": proposal.get("principal", ""),
        "object": proposal.get("object_binding", ""),
        "mutation": spec.get("mutation_policy") != "read_only",
        "payload_family": "none",
        "oracle": proposal.get("oracle", ""),
    })


__all__ = ["Scheduler", "pick_tier", "TIERS", "TRIGGER_CHECKS", "REQUIRE_CHECKS"]
