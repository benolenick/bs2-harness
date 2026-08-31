"""Deterministic finding packages and engagement reports.

This module reads Cartographer battle-state plus sanitized manager telemetry.  It
does not contact a target, choose probes, or incorporate raw target output.
"""

from __future__ import annotations

import json
from pathlib import Path

from .coverage import coverage_report


_GENERIC_REMEDIATION = "validate/encode input, enforce least privilege, patch component"

REMEDIATION_MAP = {
    "sqli": (
        "Use parameterized queries or prepared statements, validate input by allowlist, "
        "and run the database account with least privilege."
    ),
    "nosqli": (
        "Reject user-controlled query operators, enforce typed input schemas, and use "
        "least-privileged database accounts."
    ),
    "idor": (
        "Enforce object-level authorization on every request using the authenticated "
        "principal, without trusting client-supplied ownership identifiers."
    ),
    "bola": (
        "Enforce object-level authorization on every API request and verify that the "
        "authenticated principal may access the requested object."
    ),
    "lfi": (
        "Map user choices to server-side file identifiers, reject traversal sequences, "
        "and confine file access to an allowlisted directory."
    ),
    "rce": (
        "Remove command evaluation of user-controlled data, use safe APIs and strict "
        "allowlists, sandbox the service, and patch the affected component."
    ),
    "ssti": (
        "Keep user input out of template source, use sandboxed templates with automatic "
        "escaping, and patch the template engine."
    ),
    "xxe": (
        "Disable external entity and DTD processing, use a hardened parser, and restrict "
        "the service's filesystem and network access."
    ),
    "insecure-deser": (
        "Do not deserialize untrusted objects; use a simple typed data format, enforce "
        "integrity checks, allowlist types, and patch the serialization library."
    ),
    "default-creds": (
        "Remove or rotate default credentials before deployment, require unique strong "
        "secrets, and disable unused accounts."
    ),
    "auth-reset-abuse": (
        "Use single-use, high-entropy, short-lived reset tokens bound to the intended "
        "account, invalidate prior tokens, and rate-limit reset attempts."
    ),
    "xss": (
        "Apply context-aware output encoding, sanitize permitted markup, avoid unsafe DOM "
        "sinks, and deploy a restrictive Content Security Policy."
    ),
    "ssrf": (
        "Allowlist outbound destinations, resolve and validate addresses after redirects, "
        "block private and metadata ranges, and restrict service egress."
    ),
}

_PACKAGE_KEYS = (
    "id", "title", "description", "affected_asset", "vuln_class", "severity",
    "severity_rationale", "prerequisites", "reproduction", "evidence_refs",
    "demonstrated_impact", "remediation", "cleanup_status", "retest_result",
)


def load_telemetry(run_dir):
    """Best-effort index of JSONL telemetry rows by integer sequence number."""
    index = {}
    path = Path(run_dir) / "telemetry.jsonl"
    try:
        lines = path.open(encoding="utf-8")
    except (OSError, TypeError):
        return index
    with lines:
        for line in lines:
            try:
                row = json.loads(line)
                seq = int(row["seq"])
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                continue
            if isinstance(row, dict):
                index[seq] = row
    return index


def _host_label(doc, node):
    nodes = doc.get("nodes") or {}
    current = node
    seen = set()
    while isinstance(current, dict) and current.get("id") not in seen:
        seen.add(current.get("id"))
        if current.get("kind") == "host":
            meta = current.get("meta") or {}
            return str(
                meta.get("ip") or meta.get("host") or current.get("label")
                or str(current.get("id") or "").removeprefix("host:")
            )
        current = nodes.get(current.get("parent"))
    return str(doc.get("target") or "unknown target")


def _affected_asset(doc, finding):
    node_id = finding.get("node")
    node = (doc.get("nodes") or {}).get(node_id)
    if not isinstance(node, dict):
        return str(node_id or doc.get("target") or "unknown asset")
    host = _host_label(doc, node)
    label = str(node.get("label") or node.get("id") or "").strip()
    if node.get("kind") == "host" or not label or label == host:
        return host
    return f"{host} — {label}"


def _source_hypothesis(doc, finding):
    hypotheses = doc.get("hypotheses") or {}
    source_id = finding.get("from_hypothesis")
    source = hypotheses.get(source_id)
    return source if isinstance(source, dict) else None


def _prerequisites(doc, finding, source):
    if source and source.get("required_validation"):
        return str(source["required_validation"])
    node = (doc.get("nodes") or {}).get(finding.get("node")) or {}
    meta = node.get("meta") or {}
    auth_value = meta.get("auth") or meta.get("role") or meta.get("requires_auth")
    if auth_value and str(auth_value).lower() not in {"false", "none", "public", "anonymous"}:
        return "authenticated access to the affected surface"
    return "network reachability"


def _severity_rationale(severity, vuln_class):
    severity = str(severity or "info").lower()
    vuln_class = str(vuln_class or "unknown")
    return f"Rated {severity} because confirmed {vuln_class} can produce the demonstrated impact."


def _reproduction_steps(finding, telemetry_index):
    steps = []
    for ref in finding.get("evidence_refs") or []:
        command = None
        if isinstance(ref, str) and ref.startswith("telemetry:"):
            try:
                row = telemetry_index.get(int(ref.split(":", 1)[1]))
            except (ValueError, TypeError):
                row = None
            if isinstance(row, dict) and row.get("event") == "ran" and row.get("command"):
                command = str(row["command"])
        steps.append(command or str(ref))
    if not steps and finding.get("reproduction"):
        reproduction = finding["reproduction"]
        if isinstance(reproduction, list):
            steps.extend(str(step) for step in reproduction)
        else:
            steps.append(str(reproduction))
    return [f"{number}. {step}" for number, step in enumerate(steps, 1)]


def _contains_reference(value, references):
    if isinstance(value, dict):
        return any(_contains_reference(item, references) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_reference(item, references) for item in value)
    text = str(value)
    return any(reference and reference in text for reference in references)


def _cleanup_status(doc, finding):
    references = (str(finding.get("id") or ""), str(finding.get("node") or ""))
    matches = [
        obligation for obligation in (doc.get("cleanup_obligations") or [])
        if _contains_reference(obligation, references)
    ]
    return matches or "no cleanup obligations recorded"


def finding_package(doc, finding, telemetry_index):
    """Turn one confirmed finding into a reproducible, remediation-ready package."""
    source = _source_hypothesis(doc, finding)
    affected_asset = _affected_asset(doc, finding)
    vuln_class = str(finding.get("vuln_class") or "unknown")
    severity = str(finding.get("severity") or "info")
    title = str(finding.get("title") or finding.get("id") or "Untitled finding")
    package = {
        "id": finding.get("id"),
        "title": title,
        "description": str(
            finding.get("description") or f"{title} was confirmed on {affected_asset}."
        ),
        "affected_asset": affected_asset,
        "vuln_class": vuln_class,
        "severity": severity,
        "severity_rationale": _severity_rationale(severity, vuln_class),
        "prerequisites": _prerequisites(doc, finding, source),
        "reproduction": _reproduction_steps(finding, telemetry_index),
        "evidence_refs": list(finding.get("evidence_refs") or []),
        "demonstrated_impact": str(finding.get("impact") or "No additional impact recorded."),
        "remediation": REMEDIATION_MAP.get(vuln_class.lower(), _GENERIC_REMEDIATION),
        "cleanup_status": _cleanup_status(doc, finding),
        "retest_result": finding.get("retest_result", "not retested"),
    }
    # Keep the public shape auditable and resistant to accidental field leakage.
    return {key: package[key] for key in _PACKAGE_KEYS}


def _severity_counts(findings):
    counts = {"crit": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    aliases = {"critical": "crit", "crit": "crit", "high": "high",
               "medium": "med", "med": "med", "low": "low", "info": "info"}
    for finding in findings:
        counts[aliases.get(str(finding.get("severity") or "info").lower(), "info")] += 1
    return counts


def _pct_text(value):
    return f"{float(value):.1f}".rstrip("0").rstrip(".")


def engagement_report(doc, run_dir, scope=None):
    """Assemble the authoritative engagement report from existing state readers."""
    scope_coverage = coverage_report(doc, scope)
    telemetry_index = load_telemetry(run_dir)
    raw_findings = sorted(
        (finding for finding in (doc.get("findings") or []) if isinstance(finding, dict)),
        key=lambda finding: str(finding.get("id") or ""),
    )
    packages = [finding_package(doc, finding, telemetry_index) for finding in raw_findings]
    severity_counts = _severity_counts(raw_findings)
    open_ids = scope_coverage["hypotheses"]["open"]
    hypotheses = doc.get("hypotheses") or {}
    unresolved = []
    for hypothesis_id in open_ids:
        hypothesis = hypotheses.get(hypothesis_id) or {}
        unresolved.append({
            "id": hypothesis.get("id", hypothesis_id),
            "vuln_class": hypothesis.get("vuln_class"),
            "status": hypothesis.get("status"),
            "confidence": hypothesis.get("confidence"),
        })

    surface = scope_coverage["surface"]
    untested_count = len(surface["untouched"]) + len(surface["enumerating"])
    finding_count = len(packages)
    finding_word = "finding" if finding_count == 1 else "findings"
    surface_word = "surface" if untested_count == 1 else "surfaces"
    hypothesis_count = len(unresolved)
    hypothesis_word = "hypothesis" if hypothesis_count == 1 else "hypotheses"
    # honest completion (critique #11): 'complete' without a foothold is exhaustion,
    # not success — the report must never print generic COMPLETE for an unmet objective
    if scope_coverage["complete"]:
        status = ("COMPLETE — objective achieved (foothold on map)"
                  if scope_coverage.get("objective_achieved")
                  else "COMPLETE — assessment exhausted WITHOUT compromise")
    else:
        status = "INCOMPLETE"
    severity_text = (
        f"{severity_counts['crit']} critical, {severity_counts['high']} high, "
        f"{severity_counts['med']} medium, {severity_counts['low']} low, "
        f"{severity_counts['info']} informational"
    )
    completion_statement = (
        f"Engagement is {_pct_text(surface['pct'])}% covered with {finding_count} "
        f"{finding_word} ({severity_text}); {untested_count} {surface_word} untested and "
        f"{hypothesis_count} {hypothesis_word} unresolved; therefore the engagement is {status}."
    )

    return {
        "generated_ts": 0,
        "target": doc.get("target"),
        "executive_summary": {
            "coverage_pct": surface["pct"],
            "complete": scope_coverage["complete"],
            "findings_by_severity": severity_counts,
            "open_hypotheses_count": scope_coverage["hypotheses"]["open_count"],
        },
        "scope_coverage": scope_coverage,
        "findings": packages,
        "unresolved_hypotheses": unresolved,
        "cleanup_obligations": list(doc.get("cleanup_obligations") or []),
        "completion_statement": completion_statement,
    }


def _markdown_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def render_markdown(report):
    """Render a stable Markdown engagement report."""
    summary = report["executive_summary"]
    counts = summary["findings_by_severity"]
    lines = [
        f"# Penetration Test Report — {report.get('target') or 'Unknown target'}",
        "",
        "## Executive summary",
        "",
        "| Metric | Result |",
        "| --- | --- |",
        f"| Coverage | {_pct_text(summary['coverage_pct'])}% |",
        f"| Complete | {'yes' if summary['complete'] else 'no'} |",
        f"| Critical | {counts['crit']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['med']} |",
        f"| Low | {counts['low']} |",
        f"| Informational | {counts['info']} |",
        f"| Open hypotheses | {summary['open_hypotheses_count']} |",
        "",
        "## Scope coverage",
        "",
        "| Asset | State | Rituals tested | Rituals total |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in report["scope_coverage"]["surface"]["per_node"]:
        lines.append(
            f"| {row['label']} | {row['state']} | {row['done']} | {row['total']} |"
        )
    if not report["scope_coverage"]["surface"]["per_node"]:
        lines.append("| No discovered surfaces | — | 0 | 0 |")

    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.extend(["No confirmed findings were recorded.", ""])
    for finding in report["findings"]:
        lines.extend([
            f"### {finding['title']}",
            "",
            f"- ID: {finding['id']}",
            f"- Affected asset: {finding['affected_asset']}",
            f"- Vulnerability class: {finding['vuln_class']}",
            f"- Severity: {finding['severity']}",
            f"- Severity rationale: {finding['severity_rationale']}",
            f"- Prerequisites: {finding['prerequisites']}",
            f"- Evidence references: {_markdown_value(finding['evidence_refs'])}",
            f"- Cleanup status: {_markdown_value(finding['cleanup_status'])}",
            f"- Retest result: {finding['retest_result']}",
            "",
            "#### Description",
            "",
            finding["description"],
            "",
            "#### Reproduction",
            "",
        ])
        lines.extend(f"{step}" for step in finding["reproduction"])
        if not finding["reproduction"]:
            lines.append("No reproduction steps recorded.")
        lines.extend([
            "",
            "#### Demonstrated impact",
            "",
            finding["demonstrated_impact"],
            "",
            "#### Remediation",
            "",
            finding["remediation"],
            "",
        ])

    lines.extend(["## Unresolved hypotheses", ""])
    if report["unresolved_hypotheses"]:
        lines.extend([
            "| ID | Class | Status | Confidence |",
            "| --- | --- | --- | --- |",
        ])
        for hypothesis in report["unresolved_hypotheses"]:
            lines.append(
                f"| {hypothesis['id']} | {hypothesis['vuln_class']} | "
                f"{hypothesis['status']} | {hypothesis['confidence']} |"
            )
    else:
        lines.append("None.")

    lines.extend(["", "## Cleanup obligations", ""])
    if report["cleanup_obligations"]:
        lines.extend(f"- {_markdown_value(item)}" for item in report["cleanup_obligations"])
    else:
        lines.append("None recorded.")

    lines.extend([
        "",
        "## Completion statement",
        "",
        report["completion_statement"],
        "",
    ])
    return "\n".join(lines)


def retest_finding(doc, finding_id, result, note="", ts=0):
    """Record one deterministic retest result and its audit history."""
    allowed = {"fixed", "still-vulnerable", "not-retested"}
    if result not in allowed:
        raise ValueError(f"invalid retest result: {result}")
    finding = next(
        (row for row in (doc.get("findings") or []) if row.get("id") == finding_id),
        None,
    )
    if finding is None:
        raise KeyError(finding_id)
    finding["retest_result"] = result
    doc.setdefault("log", []).append({
        "ts": int(ts or 0),
        "event": "finding_retest",
        "finding_id": finding_id,
        "result": result,
        "note": note or "retest recorded",
    })
    return finding


__all__ = [
    "REMEDIATION_MAP",
    "finding_package",
    "load_telemetry",
    "engagement_report",
    "render_markdown",
    "retest_finding",
]
