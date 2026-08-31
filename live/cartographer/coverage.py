"""Deterministic cross-phase coverage derived from a Cartographer ledger.

This module is a reader only: it never mutates the ledger, chooses work, or
contacts a target.  Its report is the authoritative completion view consumed by
the manager.
"""

from __future__ import annotations

from .model import DEAD, ENUMERATING, EXHAUSTED, FOOTHOLD, UNTOUCHED, UNVERIFIED, _rituals_for


SURFACE_KINDS = {"port", "endpoint", "app", "vhost", "share", "host",
                 # interior post-foothold frontier counts toward engagement completion too
                 "identity", "localenum", "privesc", "netview"}
RESOLVED_HYPOTHESIS_STATUSES = ("confirmed", "rejected", "inconclusive")
_ATTACK_RITUALS = {"cve-lookup", "default-creds", "known-exploit-chain"}


def surface_coverage(doc):
    """Return ritual and lifecycle coverage for every discovered surface node."""
    per_node = []
    untouched = []
    enumerating = []
    closed = []
    rituals_done_sum = 0
    rituals_total_sum = 0

    for node_id in sorted((doc.get("nodes") or {})):
        node = doc["nodes"][node_id]
        if node.get("kind") not in SURFACE_KINDS:
            continue
        if node.get("state") == UNVERIFIED:
            # a fuzz artifact awaiting content verification is not surface yet — it must
            # neither block completion nor count against the ritual denominator
            continue
        rituals = set(_rituals_for(node))
        done = len(set(node.get("rituals_done") or []) & rituals)
        total = len(rituals)
        label = node.get("label") or node_id
        state = node.get("state")
        rituals_done_sum += done
        rituals_total_sum += total
        per_node.append({
            "id": node_id,
            "label": label,
            "state": state,
            "done": done,
            "total": total,
        })
        if state == UNTOUCHED:
            untouched.append(label)
        elif state == ENUMERATING:
            enumerating.append(label)
        elif state in {EXHAUSTED, FOOTHOLD, DEAD}:
            closed.append(label)

    pct = (0.0 if not per_node
           else 100.0 if rituals_total_sum == 0
           else 100.0 * rituals_done_sum / rituals_total_sum)
    return {
        "pct": pct,
        "untouched": untouched,
        "enumerating": enumerating,
        "closed": closed,
        "per_node": per_node,
    }


def hypothesis_coverage(doc):
    """Group hypothesis ids by lifecycle status and count open/resolved work."""
    grouped = {
        "open": [],
        "confirmed": [],
        "rejected": [],
        "inconclusive": [],
    }
    for hypothesis_id in sorted((doc.get("hypotheses") or {})):
        hypothesis = doc["hypotheses"][hypothesis_id]
        status = hypothesis.get("status")
        if status in {"proposed", "testing"}:
            grouped["open"].append(hypothesis_id)
        elif status in RESOLVED_HYPOTHESIS_STATUSES:
            grouped[status].append(hypothesis_id)
    grouped["open_count"] = len(grouped["open"])
    grouped["resolved_count"] = sum(
        len(grouped[status]) for status in RESOLVED_HYPOTHESIS_STATUSES
    )
    return grouped


def unattacked_apps(doc):
    """DEPTH FLOOR: identified apps on which NO attack ritual has ever run. Coverage must
    reward ATTACK receipts, not just discovery receipts — a run can enumerate to 100%
    without ever firing an exploit (runs 741-745: osTicket/GitLab fingerprinted for whole
    budgets, zero validated exploits). An identified product is attackable the moment it
    has a name; version-precision is NOT a precondition for cve-lookup."""
    out = []
    for node in (doc.get("nodes") or {}).values():
        if node.get("kind") != "app" or node.get("state") in {DEAD, FOOTHOLD}:
            continue
        meta = node.get("meta") or {}
        ident = str(meta.get("app") or meta.get("product")
                    or node.get("label") or node.get("id")).strip()
        if not ident:
            continue
        if set(node.get("rituals_done") or []) & _ATTACK_RITUALS:
            continue
        out.append(f"{ident} {str(meta.get('version') or '').strip()}".strip())
    return out


def cleanup_obligations(doc):
    """Expose the cleanup ledger without modifying the source document."""
    return list(doc.get("cleanup_obligations") or [])


def _scope_blockers(doc, scope):
    blockers = []
    nodes = (doc.get("nodes") or {}).values()
    host_handles = set()
    for node in nodes:
        if node.get("kind") != "host":
            continue
        host_handles.update(str(value) for value in (
            node.get("id"), node.get("label"),
            (node.get("meta") or {}).get("host"),
            (node.get("meta") or {}).get("ip"),
        ) if value is not None)
    for host in scope.get("required_hosts") or []:
        if str(host) not in host_handles and f"host:{host}" not in host_handles:
            blockers.append(f"required host missing: {host}")

    present_classes = {
        str(row.get("vuln_class"))
        for row in (doc.get("hypotheses") or {}).values()
        if row.get("vuln_class") is not None
    }
    present_classes.update(
        str(row.get("vuln_class"))
        for row in (doc.get("findings") or [])
        if isinstance(row, dict) and row.get("vuln_class") is not None
    )
    for vuln_class in scope.get("required_classes") or []:
        if str(vuln_class) not in present_classes:
            blockers.append(f"required vulnerability class missing: {vuln_class}")
    return blockers


def coverage_report(doc, scope=None):
    """Derive the single authoritative engagement-completion report."""
    surface = surface_coverage(doc)
    hypotheses = hypothesis_coverage(doc)
    cleanup_pending = cleanup_obligations(doc)
    blockers = []

    if not surface["per_node"]:
        blockers.append("no_surface_discovered: map is empty or uninitialized")
    if surface["untouched"]:
        blockers.append(
            f"{len(surface['untouched'])} surfaces never enumerated: "
            + ", ".join(surface["untouched"])
        )
    if surface["enumerating"]:
        blockers.append(
            f"{len(surface['enumerating'])} surfaces still enumerating: "
            + ", ".join(surface["enumerating"])
        )
    if hypotheses["open_count"]:
        blockers.append(
            f"{hypotheses['open_count']} hypotheses unresolved: "
            + ", ".join(hypotheses["open"])
        )
    unattacked = unattacked_apps(doc)
    if unattacked:
        blockers.append(
            f"{len(unattacked)} identified apps never attacked "
            f"(cve-lookup/default-creds/known-exploit-chain): " + ", ".join(unattacked[:6])
        )
    if cleanup_pending:
        noun = "obligation" if len(cleanup_pending) == 1 else "obligations"
        blockers.append(f"{len(cleanup_pending)} cleanup {noun} pending")
    if scope is not None:
        blockers.extend(_scope_blockers(doc, scope))

    # objective accounting (critique #11): discovery coverage and OBJECTIVE ACHIEVED are
    # different facts. A surveyed map with no foothold is "assessment exhausted without
    # compromise", never a generic success.
    objective_achieved = any(
        n.get("state") == FOOTHOLD and n.get("kind") == "host"
        for n in (doc.get("nodes") or {}).values())
    outcome = ("objective_achieved" if objective_achieved
               else "exhausted_without_compromise" if not blockers
               else "incomplete")
    return {
        "surface": surface,
        "hypotheses": hypotheses,
        "findings_count": len(doc.get("findings") or []),
        "unattacked_apps": unattacked,
        "cleanup_pending": cleanup_pending,
        "scope": scope,
        "complete": not blockers,
        "objective_achieved": objective_achieved,
        "outcome": outcome,
        "blockers": blockers,
    }


TERMINAL_STATES = ("assessment_complete", "closure_complete", "stopped_incomplete")


def terminal_projection(doc, scope=None, stopped=False):
    """The P1-6 terminal projection (re-audit 2026-08-25): exactly one closed state,
    derived from the SAME coverage report every consumer reads.

    - assessment_complete: scope present, coverage complete, hypotheses resolved,
      findings evidence-backed, cleanup discharged.
    - closure_complete: assessment_complete AND every confirmed finding has a retest
      outcome (the remediation disposition rides in the finding package).
    - stopped_incomplete: forced stop or incomplete coverage — a stop NEVER projects
      as a variant of complete.
    - missing/corrupt scope blocks BOTH complete states: projection is None.

    Returns {"projection": str|None, "reason": str}. The reason is bounded prose for
    the audit trail, never a secret (it names blockers, finding ids, state names only).
    """
    if scope is None or not (scope.get("hosts") or scope.get("ports")):
        return {"projection": None, "reason": "blocked: missing or corrupt scope"}
    report = coverage_report(doc, scope)
    if stopped or not report["complete"]:
        # stopped may be a REASON STRING ('done_forced' | 'stop') naming how the run
        # ended, or True for a plain forced stop
        reason = (stopped if isinstance(stopped, str) else "forced stop"
                  ) if stopped else "; ".join(report["blockers"])[:240] or "coverage incomplete"
        return {"projection": "stopped_incomplete", "reason": reason}
    findings = doc.get("findings") or []
    unverified = [str(f.get("id")) for f in findings if not f.get("evidence_refs")]
    if unverified:
        return {"projection": "stopped_incomplete",
                "reason": "findings without verified evidence: " + ", ".join(unverified)}
    if findings and all(f.get("retest_result") for f in findings):
        return {"projection": "closure_complete",
                "reason": "all confirmed findings remediated and retested"}
    return {"projection": "assessment_complete",
            "reason": "scope covered, hypotheses resolved, cleanup discharged"}


def render(doc, scope=None):
    """Render one short, content-blind completion summary."""
    report = coverage_report(doc, scope)
    pct = f"{report['surface']['pct']:.1f}".rstrip("0").rstrip(".")
    untouched = len(report["surface"]["untouched"])
    open_count = report["hypotheses"]["open_count"]
    findings_count = report["findings_count"]
    finding_word = "finding" if findings_count == 1 else "findings"
    if report["complete"]:
        status = ("COMPLETE — objective achieved (foothold)" if report["objective_achieved"]
                  else "COMPLETE — assessment exhausted WITHOUT compromise")
    else:
        status = "INCOMPLETE"
    if report["blockers"]:
        status += f": {report['blockers'][0]}"
    return (
        f"COVERAGE {pct}% surface enumerated | {untouched} untouched | "
        f"{open_count} open hypotheses | {findings_count} {finding_word} | {status}"
    )


__all__ = [
    "SURFACE_KINDS",
    "surface_coverage",
    "hypothesis_coverage",
    "unattacked_apps",
    "cleanup_obligations",
    "coverage_report",
    "render",
]
