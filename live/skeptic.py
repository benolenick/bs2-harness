#!/usr/bin/env python3
"""skeptic — the disprove-first verifier, woken only for high/critical claims (BS2 doc §9).

When a specialist thinks it has a high or critical finding, wake a SEPARATE verifier
with a tiny context — claim, control request, test request, structured delta, relevant
state, proposed impact, evidence receipts — whose job is to DISPROVE the finding, not
to agree with it. This costs far less than running two agents throughout the whole
engagement.

This module builds the tiny context deterministically and carries the checklist; the
LLM (or a human) answers the questions. build_brief + checklist output is the skeptic
harness the manager loop hands to a fresh, small-context model.
"""
from __future__ import annotations

DISPROVE_CHECKLIST = [
    ("intentional_public", "Is the object intentionally public (no authz intended)?"),
    ("ownership_actually_different", "Are the two objects actually owned by different principals?"),
    ("test_changed_state", "Did the TEST request change state (not a clean comparison)?"),
    ("response_cached", "Was the response cached/served from a shared cache?"),
    ("session_switched", "Did the session silently switch identities between requests?"),
    ("verbose_error_only", "Is this just verbose error behavior, not data exposure?"),
    ("impact_inferred", "Is impact being inferred rather than demonstrated?"),
]


def build_brief(finding):
    """Tiny-context skeptic brief: everything needed to disprove, nothing else."""
    delta = finding.get("delta") or {}
    lines = [
        f"CLAIM: {finding.get('claim', '?')}",
        f"IMPACT: {finding.get('impact', '?')}",
        f"CONTROL REQUEST: {finding.get('control_request') or delta.get('control_request') or '?'}",
        f"TEST REQUEST: {finding.get('test_request') or delta.get('test_request') or '?'}",
        "STRUCTURED DELTA: "
        + (json_compact(delta) if delta else "?"),
        "STATE: " + (finding.get("state", "?")),
        "EVIDENCE: " + ", ".join(finding.get("evidence_refs") or [] or ["?"]),
        "",
        "Your job is to DISPROVE this finding. Answer each question with "
        "yes/disproved or no/stands:",
    ]
    for key, question in DISPROVE_CHECKLIST:
        lines.append(f"- [{key}] {question}")
    return "\n".join(lines)


def json_compact(obj):
    import json
    return json.dumps(obj, separators=(",", ":"), default=str)


def verdict_from(answers):
    """answers: {checklist_key: True (disproved) | False (stands)}. FAIL-CLOSED (P0-4):
    every checklist question must be answered — unanswered questions mean `inconclusive`,
    NEVER confirmed. With all questions answered, one solid disprover rejects the finding;
    only a fully answered checklist with no disprover confirms it."""
    answers = answers or {}
    missing = [key for key, _q in DISPROVE_CHECKLIST if key not in answers]
    if missing:
        return {"survives": False, "verdict": "inconclusive", "missing": missing}
    disprovers = [key for key, _q in DISPROVE_CHECKLIST if answers.get(key)]
    if disprovers:
        return {"survives": False, "verdict": "rejected", "disproved_by": disprovers}
    return {"survives": True, "verdict": "confirmed"}


__all__ = ["DISPROVE_CHECKLIST", "build_brief", "verdict_from"]
