#!/usr/bin/env python3
"""intake_feed — build the BS2 LEFT "Live intake" panel from the REAL governed run.

The green BattleStation 2.0 page has a left waterfall (Memoria / Recon / Loot /
Critic / Confirmed-negatives / Leads) that shipped as a canned Active-Directory
replay (WEB01->DC01, ZeroLogon, Kerberoast...). This projects the ACTUAL run —
the same findings.jsonl + surface.json that drive the map — into a small
intake.json the page fetches, so the left panel tells the SAME story as the map.

Content-blind: only NON-SECRET finding labels (mandated non-secret by the seam
brief), endpoint paths, methods, and vuln-CLASS names cross over — never a
response body, token, or secret value.

  python3 intake_feed.py --run-dir <grun> --out <static>/intake.json
"""
from __future__ import annotations
import argparse, json, re, time
from pathlib import Path
from collections import Counter

# how a discovered class reads as a candidate technique in the Memoria lane
CLASS_TECH = {
    "auth-bypass":            ("login SQLi auth bypass", "' OR 1=1-- yields admin JWT"),
    "sqli":                   ("UNION-based SQLi",       "enumerate users table"),
    "nosqli":                 ("NoSQL operator injection", "$ne / $gt mass-update"),
    "broken-access-control":  ("Broken access control / IDOR", "object-id horizontal walk"),
    "xss":                    ("Stored / DOM XSS",       "unsanitised sink"),
    "path-traversal":         ("Path traversal",         "../ static-file escape"),
    "llm-injection":          ("LLM prompt injection",   "chatbot guardrail bypass"),
}


def _path_from_label(label: str) -> str:
    m = re.search(r"(/[A-Za-z0-9_./-]+)", label or "")
    return m.group(1).rstrip(".,") if m else ""


def build(run: Path, live: bool = False, running: bool = False) -> dict:
    seam = json.loads((run / "seam.json").read_text())
    host = seam.get("host", "target")
    port = ""
    m = re.search(r":(\d+)", seam.get("target", ""))
    if m:
        port = m.group(1)

    surface = json.loads((run / "surface.json").read_text()) if (run / "surface.json").exists() else {}
    endpoints = surface.get("endpoints", [])
    classes = surface.get("counts", {}).get("classes", [])

    areas = Counter()
    for e in endpoints:
        seg = (e.get("path", "/").strip("/").split("/")[0] or "root")
        areas[seg] += 1

    findings = []
    confirmed_classes = set()
    if (run / "findings.jsonl").exists():
        for ln in (run / "findings.jsonl").read_text().splitlines():
            try:
                f = json.loads(ln)
            except Exception:
                continue
            cls = f.get("vuln_class", "")
            confirmed_classes.add(cls)
            findings.append({
                "class": cls,
                "sev": f.get("severity", ""),
                "label": f.get("label", ""),
                "path": _path_from_label(f.get("label", "")),
            })

    # honest split: a class the mapper surfaced but no finding confirmed is a
    # real explored-then-ruled-out negative, not a fabricated one.
    explored = [c for c in classes if c not in confirmed_classes]

    # recon FACTS — all true, all from the surface projection
    recon = [
        f"{len(endpoints)} endpoints mapped",
        "REST API under " + ", ".join(f"/{a}" for a, _ in areas.most_common(2)),
        f"{len(classes)} vuln-classes surfaced by the mapper",
    ]
    if any(a == ".git" for a, _ in areas.items()):
        recon.append("/.git exposed — source recoverable")
    if any(a == "ftp" for a, _ in areas.items()):
        recon.append("/ftp directory listing reachable")

    # techniques (Memoria lane) — confirmed classes score high (they landed),
    # explored-only classes score lower and get pruned by the critic lane.
    techniques = []
    for c in classes:
        op, sub = CLASS_TECH.get(c, (c, ""))
        good = c in confirmed_classes
        techniques.append({
            "ref": c, "op": op, "sub": sub,
            "good": good, "score": 0.9 if good else 0.62,
        })

    pruned = [{"op": CLASS_TECH.get(c, (c, ""))[0],
               "why": "explored — no exploitable instance confirmed"}
              for c in explored]

    owned = sorted({f["path"] for f in findings if f["path"]})
    fr = [e.get("path") for e in endpoints if e.get("path") and e.get("path") not in owned]

    return {
        "live": bool(live),
        "status": {"running": bool(running)},
        "generation": int(time.time()),
        "target": {
            "label": "juice-shop" if "juice" in seam.get("target", "").lower() or port == "3060" else host,
            "host": f"{host}:{port}" if port else host,
            "goal1": "admin JWT via login SQLi",
            "goal2": "post-auth loot + breadth",
        },
        "recon": recon,
        "techniques": techniques,
        "findings": findings,
        "pruned": pruned,
        "owned": owned,
        "frontier_sample": fr[:14],
        "flag": f"{len(findings)} verified findings · {len(confirmed_classes)} classes ("
                + ", ".join(sorted(confirmed_classes)) + ")",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--out", action="append", required=True,
                    help="output intake.json path (repeatable — write to each static dir)")
    ap.add_argument("--live", action="store_true", help="mark intake for live-poll mode")
    ap.add_argument("--running", action="store_true", help="attack still in progress")
    a = ap.parse_args()
    data = build(Path(a.run_dir), live=a.live, running=a.running)
    for out in a.out:
        Path(out).write_text(json.dumps(data, indent=2))
        print(f"wrote {out}  ({len(data['findings'])} findings, {len(data['techniques'])} techniques, {len(data['owned'])} owned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
