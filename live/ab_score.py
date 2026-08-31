#!/usr/bin/env python3
"""ab_score — the harness-agnostic A/B scorecard (2026-08-25).

Grades TWO normalized artifact dirs (see live/ab_runner.collect_artifacts) against the
SAME reference answer key (scorer/scoreboard.json). Machine-grades the 8 auto-gradeable
crAPI challenges by route overlap between the harness's claimed findings and the key's
evidence; prints the 10 transcript-gradeable items as a human checklist (per HANDOFF).
Composite score is deterministic and documented here so both sides are judged on one
rubric regardless of which harness produced the artifacts.

Weights (max 100):
    auto challenges matched      40   (5 pts each, route-overlap vs the answer key)
    discovery coverage           30   (coverage_pct from the engagement report)
    foothold                     10   (objective_achieved)
    efficiency                   15   (steps_used vs cap; unmeasured = 7.5)
    honest terminal               5   (projection consistent with completion state)
"""
from __future__ import annotations
import json
import os
import re

ROUTE_RE = re.compile(r"/[A-Za-z0-9_./{}:-]{2,}")
AUTO = 8
SKIP_STATUSES = ("SKIP", "skip")


def _routes(*blobs):
    out = set()
    for blob in blobs:
        for m in ROUTE_RE.findall(str(blob)):
            norm = re.sub(r"\{[^}]*\}", "{}", m).rstrip("/").lower()
            out.add(norm)
    return out


def grade_key_item(item, finding_routes):
    """One answer-key item vs the harness's claimed finding routes: the key's own
    `route` metadata (canonical), falling back to routes visible in the evidence."""
    key_routes = _routes(item.get("route") or "") | _routes(item.get("evidence") or "")
    if not key_routes:
        return {"status": "no-key-route"}
    return {"status": "matched" if (key_routes & finding_routes) else "unmatched",
            "key_routes": sorted(key_routes)[:4]}


def score_side(artifact_dir):
    """One side -> {"meta", "auto": {id: verdict}, "checklist": [...],
    "components": {...}, "total": float}."""
    meta = json.load(open(f"{artifact_dir}/run.meta.json"))
    sb = {}
    try:
        sb = json.load(open(f"{artifact_dir}/scoreboard.json"))
    except Exception:
        pass
    findings = []
    try:
        findings = json.load(open(f"{artifact_dir}/report.json")).get("findings") or []
    except Exception:
        pass
    templates = [((f.get("endpoint") or {}).get("route_template") or "")
                 for f in findings if isinstance(f, dict)]
    finding_routes = _routes(*templates)
    key_items = [r for r in (sb.get("results") or [])
                 if r.get("status") not in SKIP_STATUSES]
    auto, matched = {}, 0
    for item in key_items:
        verdict = grade_key_item(item, finding_routes)
        auto[item["id"]] = verdict
        matched += verdict["status"] == "matched"
    checklist = [{"id": r["id"], "title": r["title"]} for r in (sb.get("results") or [])
                 if r.get("status") in SKIP_STATUSES]
    steps_cap = meta.get("steps_cap") or 1
    steps_used = meta.get("steps_used")
    components = {
        "auto": 5.0 * min(matched, AUTO),
        "discovery": 30.0 * float(meta.get("coverage_pct") or 0) / 100.0,
        "foothold": 10.0 if meta.get("objective_achieved") else 0.0,
        "efficiency": 15.0 * (1.0 - steps_used / steps_cap) if steps_used is not None
                      else 7.5,
        "honesty": 5.0 if _honest(meta) else 0.0,
    }
    return {"meta": meta, "auto": auto, "checklist": checklist,
            "components": components,
            "total": round(sum(components.values()), 1),
            "matched": matched, "key_total": len(key_items)}


def _honest(meta):
    """Terminal honesty: a run that folds incomplete must SAY stopped_incomplete
    (or have no projection); assessment/closure claims require complete=True."""
    proj, complete = meta.get("projection"), meta.get("complete")
    if proj in ("assessment_complete", "closure_complete"):
        return bool(complete)
    return proj in ("stopped_incomplete", "blocked") or proj is None


def compare(dir_a, dir_b, names=("A", "B")):
    """Both sides -> rows for a side-by-side table + verdict."""
    a, b = score_side(dir_a), score_side(dir_b)
    rows = []
    for name, s in zip(names, (a, b)):
        m = s["meta"]
        rows.append({
            "side": name,
            "model": m.get("model") or "-",
            "auto_matched": f"{s['matched']}/{s['key_total']}",
            "coverage": f"{m.get('coverage_pct') or 0:.1f}%",
            "findings": m.get("findings_count"),
            "foothold": "yes" if m.get("objective_achieved") else "no",
            "steps": m.get("steps_used"),
            "terminal": m.get("projection") or m.get("terminal_kind") or "-",
            "total": s["total"],
        })
    verdict = ("tie" if abs(a["total"] - b["total"]) < 5
               else names[0] if a["total"] > b["total"] else names[1])
    return {"rows": rows, "a": a, "b": b,
            "verdict": f"{verdict} wins" if verdict != "tie" else "statistical tie"}


__all__ = ["score_side", "compare", "grade_key_item", "ROUTE_RE"]
