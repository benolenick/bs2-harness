#!/usr/bin/env python3
"""zap adapter — governed ZAP via its Automation Framework (YAML jobs). Passive-first:
the active scan job appears only under an explicit unlock. ZAP alerts normalize like
nuclei results: leads (hypotheses), never findings."""
import json

try:
    from observation import ObservationRecord
except ImportError:
    from ..observation import ObservationRecord

RISK_CONFIDENCE = {"3": "high", "2": "medium", "1": "low", "0": "low"}


def gate(ctx):
    """Active scanning mutates state — gated behind an explicit unlock."""
    ctx = ctx or {}
    if ctx.get("active") and not ctx.get("unlock"):
        return False, "active scan gated: requires explicit mutation unlock"
    return True, "ok"


def automation_yaml(target, run_dir, active=False, spider=True):
    """The ZAP Automation Framework job spec handed to the executor. Passive-first:
    the active job appears only when unlocked."""
    lines = [
        "env:",
        "  contexts:",
        "    - name: default",
        "      urls:",
        f"        - {target}",
        "  parameters:",
        "    failOnError: false",
        "    progressToStdout: true",
        "jobs:",
        "  - type: passiveScan-config",
        "    parameters:",
        "      maxAlertsPerRule: 10",
    ]
    if spider:
        lines += [
            "  - type: spider",
            "    parameters:",
            f"      url: {target}",
            "      maxDuration: 2",
        ]
    lines += ["  - type: passiveScan-wait",
              "    parameters: {maxDuration: 5}"]
    if active:
        lines += [
            "  - type: activeScan",
            "    parameters:",
            f"      url: {target}",
            "  - type: activeScan-wait",
            "    parameters: {maxDuration: 5}",
        ]
    lines += [
        "  - type: report",
        "    parameters:",
        "      template: traditional-json",
        f"      reportFile: {run_dir}/zap-report.json",
    ]
    return "\n".join(lines)


def _route(uri):
    path = uri.split("://", 1)[-1] if "://" in uri else uri
    return "/" + path.split("/", 1)[1] if "/" in path else uri


def adapt(raw, ctx=None):
    """Parses the traditional-json report: every alert becomes a hypothesis record
    (lead), the instance URI folds into the map."""
    ctx = ctx or {}
    try:
        report = json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return {"records": [], "folds": []}
    records, folds = [], []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            for inst in (alert.get("instances") or [{}])[:1]:
                uri = inst.get("uri") or site.get("@name", "")
                route = _route(uri) if uri else "template://"
                records.append(ObservationRecord(
                    target=ctx.get("target", ""),
                    endpoint={"id": f"zap:{alert.get('pluginid', '?')}",
                              "method": inst.get("method", "GET"),
                              "route_template": route},
                    principal=ctx.get("principal", "anon"),
                    tenant=ctx.get("tenant", ""),
                    map_node=ctx.get("map_node", "unmapped"),
                    tool={"name": "zap", "version": report.get("@version", "unknown"),
                          "configuration": {"plugin": alert.get("pluginid"),
                                            "alert_ref": alert.get("alertRef")}},
                    evidence=[f"zap-report:{alert.get('pluginid', '?')}"],
                    confidence=RISK_CONFIDENCE.get(str(alert.get("riskcode")), "low"),
                    reproducible=False,
                    state_mutated=bool(ctx.get("active")),
                    kind="hypothesis", confirmation_status="unconfirmed",
                ))
                if uri and inst.get("method"):
                    folds.append(f"endpoint={inst['method']} {route}")
    return {"records": records, "folds": folds}
