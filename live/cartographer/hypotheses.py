"""Deterministic vulnerability-hypothesis lifecycle for Cartographer ledgers.

This module owns bookkeeping only.  It turns sanitized signal notes into durable
hypotheses, ranks open work, and promotes manager-confirmed hypotheses to findings.
It never chooses or executes a validation probe and never sees raw command output.
"""

from __future__ import annotations


PREDICATE_MAP = {
    "injectable": (
        "sqli",
        "Confirm with a boolean/time-based true-vs-false pair on the param; obtain ONE proof value only, do not exfiltrate data.",
        "high",
    ),
    "nosql_injectable": (
        "nosqli",
        "Confirm operator-injection changes the result set (authz-neutral).",
        "high",
    ),
    "serves_file_by_param": (
        "lfi",
        "Confirm inclusion with a bounded read of a known-benign local path; no secrets.",
        "high",
    ),
    "template_engine": (
        "ssti",
        "Confirm evaluation with an arithmetic marker (e.g. 7*7) — no code exec.",
        "high",
    ),
    "xxe_vulnerable": (
        "xxe",
        "Confirm external-entity parsing with a benign local/OOB marker.",
        "high",
    ),
    "insecure_deserialization": (
        "insecure-deser",
        "Confirm a benign gadget marker; no RCE.",
        "critical",
    ),
    "reset_flow": (
        "auth-reset-abuse",
        "Confirm token predictability/leak across two accounts.",
        "medium",
    ),
}

CONF_W = {"low": 1, "medium": 2, "high": 3}
SEV_W = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
REACH = {
    "untouched": 1.0,
    "enumerating": 0.8,
    "exhausted": 0.3,
    "led-to-foothold": 0.25,
    "dead": 0.1,
}
OPEN_STATUSES = {"proposed", "testing"}
VERDICTS = {"confirmed", "rejected", "inconclusive"}


def _stores(doc):
    doc.setdefault("hypotheses", {})
    doc.setdefault("findings", [])


def _unique_extend(dst, values):
    for value in values or []:
        if value not in dst:
            dst.append(value)


def hyp_id(node, vuln_class, locus):
    """Return the stable de-duplication identity for a hypothesis."""
    return f"{node}|{vuln_class}|{locus}"


def raise_hypothesis(doc, node, vuln_class, locus, title, raised_from, confidence,
                     required_validation, impact, severity, ts):
    """Create or merge a hypothesis without resetting its lifecycle state."""
    _stores(doc)
    if confidence not in CONF_W:
        raise ValueError(f"invalid confidence: {confidence}")
    if severity not in SEV_W:
        raise ValueError(f"invalid severity: {severity}")
    ts = int(ts or 0)
    hid = hyp_id(node, vuln_class, locus)
    existing = doc["hypotheses"].get(hid)
    if existing is not None:
        _unique_extend(existing.setdefault("raised_from", []), raised_from)
        old_confidence = existing.get("confidence", "low")
        if CONF_W[confidence] > CONF_W.get(old_confidence, 0):
            existing["confidence"] = confidence
        existing["last_ts"] = ts
        existing.setdefault("history", []).append({
            "ts": ts,
            "status": existing.get("status", "proposed"),
            "note": "duplicate signal merged",
        })
        return hid

    doc["hypotheses"][hid] = {
        "id": hid,
        "node": node,
        "vuln_class": vuln_class,
        "locus": locus,
        "title": title,
        "raised_from": list(dict.fromkeys(raised_from or [])),
        "confidence": confidence,
        "status": "proposed",
        "required_validation": required_validation,
        "evidence_refs": [],
        "impact": impact,
        "severity": severity,
        "attempts": 0,
        "first_ts": ts,
        "last_ts": ts,
        "history": [{"ts": ts, "status": "proposed", "note": "raised"}],
    }
    return hid


def raise_from_signals(doc, ts):
    """Raise general hypotheses from signal notes on endpoint and app nodes."""
    _stores(doc)
    ids = []
    for node_id in sorted((doc.get("nodes") or {})):
        node = doc["nodes"][node_id]
        if node.get("kind") not in {"endpoint", "app"}:
            continue
        locus = (node.get("meta") or {}).get("handle") or node_id
        for note in node.get("notes") or []:
            if not isinstance(note, str) or not note.startswith("signal:"):
                continue
            predicate = note.split(":", 2)[1]
            mapped = PREDICATE_MAP.get(predicate)
            if mapped is None:
                continue
            vuln_class, required_validation, severity = mapped
            hid = raise_hypothesis(
                doc,
                node=node_id,
                vuln_class=vuln_class,
                locus=locus,
                title=f"Potential {vuln_class} at {locus}",
                raised_from=[note],
                confidence="medium",
                required_validation=required_validation,
                impact=f"Potential {vuln_class} impact if validated.",
                severity=severity,
                ts=ts,
            )
            if hid not in ids:
                ids.append(hid)
    return ids


def set_testing(doc, id, ts, note=""):
    """Move a proposed hypothesis into testing and count the bounded attempt."""
    _stores(doc)
    hyp = doc["hypotheses"][id]
    if hyp.get("status") != "proposed":
        return id
    ts = int(ts or 0)
    hyp["status"] = "testing"
    hyp["attempts"] = int(hyp.get("attempts") or 0) + 1
    hyp["last_ts"] = ts
    hyp.setdefault("history", []).append({
        "ts": ts,
        "status": "testing",
        "note": note or "validation started",
    })
    return id


def resolve(doc, id, verdict, evidence_refs, reason, ts):
    """Record a manager verdict and retain all positive or negative evidence refs."""
    _stores(doc)
    if verdict not in VERDICTS:
        raise ValueError(f"invalid verdict: {verdict}")
    hyp = doc["hypotheses"][id]
    ts = int(ts or 0)
    _unique_extend(hyp.setdefault("evidence_refs", []), evidence_refs)
    hyp["status"] = verdict
    hyp["last_ts"] = ts
    hyp.setdefault("history", []).append({"ts": ts, "status": verdict, "note": reason})
    if verdict == "confirmed":
        return promote_to_finding(doc, id, ts=ts)
    return None


def promote_to_finding(doc, id, reproduction="", ts=0):
    """Promote one confirmed hypothesis to exactly one durable finding."""
    _stores(doc)
    hyp = doc["hypotheses"][id]
    if hyp.get("status") != "confirmed":
        raise ValueError("only a confirmed hypothesis can become a finding")
    finding_id = f"finding|{id}"
    existing = next((f for f in doc["findings"]
                     if f.get("from_hypothesis") == id), None)
    if existing is not None:
        _unique_extend(existing.setdefault("evidence_refs", []), hyp.get("evidence_refs") or [])
        if reproduction and not existing.get("reproduction"):
            existing["reproduction"] = reproduction
        return existing.get("id", finding_id)
    doc["findings"].append({
        "id": finding_id,
        "from_hypothesis": id,
        "title": hyp["title"],
        "node": hyp["node"],
        "vuln_class": hyp["vuln_class"],
        "severity": hyp["severity"],
        "impact": hyp["impact"],
        "evidence_refs": list(hyp.get("evidence_refs") or []),
        "reproduction": reproduction,
        "status": "confirmed",
        "ts": int(ts or 0),
    })
    return finding_id


def rank(doc):
    """Return open hypotheses ordered by deterministic severity/confidence/reach score."""
    _stores(doc)
    rows = []
    nodes = doc.get("nodes") or {}
    for hid, hyp in doc["hypotheses"].items():
        if hyp.get("status") not in OPEN_STATUSES:
            continue
        node_state = (nodes.get(hyp.get("node")) or {}).get("state")
        reach = REACH.get(node_state, 0.5)
        attempts = int(hyp.get("attempts") or 0)
        score = (SEV_W.get(hyp.get("severity"), 0)
                 * CONF_W.get(hyp.get("confidence"), 0)
                 * reach / (1 + attempts))
        row = dict(hyp)
        row["score"] = score
        rows.append(row)
    rows.sort(key=lambda row: (-row["score"], row["id"]))
    return rows


def open_hypotheses(doc, top=8):
    return rank(doc)[:max(0, int(top))]


def render(doc):
    """Render a compact, stable human view of the hypothesis register."""
    _stores(doc)
    out = ["id | class@node | status | conf | sev"]
    for hid in sorted(doc["hypotheses"]):
        hyp = doc["hypotheses"][hid]
        out.append(
            f"{hid} | {hyp['vuln_class']}@{hyp['node']} | {hyp['status']} | "
            f"{hyp['confidence']} | {hyp['severity']}"
        )
    return "\n".join(out)


def required_validation_for_class(vuln_class):
    """Share the general validation guidance with manager-raised hypotheses."""
    for mapped_class, validation, _severity in PREDICATE_MAP.values():
        if mapped_class == vuln_class:
            return validation
    return "Confirm with one bounded, non-destructive proof marker; do not exfiltrate data."


__all__ = [
    "PREDICATE_MAP",
    "CONF_W",
    "SEV_W",
    "REACH",
    "hyp_id",
    "raise_hypothesis",
    "raise_from_signals",
    "set_testing",
    "resolve",
    "promote_to_finding",
    "rank",
    "open_hypotheses",
    "render",
    "required_validation_for_class",
]
