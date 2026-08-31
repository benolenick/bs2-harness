#!/usr/bin/env python3
"""manager_feed — emit the CONTENT-BLIND manager view as manager.json for the BS2 dock.

The governed ledger IS the manager's window into a run: event-type tallies, verified
findings (non-secret labels), and denied gates — never raw exploit bodies. This projects
that into a small same-origin JSON the BattleStation 2.0 terminal dock polls, so the
manager feed shows INSIDE the page next to the map (CSP connect-src 'self' — same origin).

  python3 manager_feed.py --run-dir <grun> [--running] --out <static>/manager.json ...
"""
from __future__ import annotations
import argparse, json, subprocess, time, re
from pathlib import Path
from collections import Counter

SEAM = "/opt/bs2/live/governed_seam.py"


def _seam(run: Path, verb: str) -> str:
    try:
        r = subprocess.run(["python3", SEAM, verb, "--run-dir", str(run)],
                           capture_output=True, text=True, timeout=30)
        return r.stdout or ""
    except Exception:
        return ""


def build(run: Path, running: bool) -> dict:
    ev = _seam(run, "events")
    c: Counter = Counter()
    for ln in ev.splitlines():
        tok = ln.strip().split()
        if tok and "." in tok[0]:
            c[tok[0]] += 1

    counts = {
        "dispatched": c.get("tool.dispatched", 0),
        "completed":  c.get("tool.completed", 0),
        "verified":   c.get("tool.verified", 0),
        "denied":     c.get("tool.denied", 0),
        "caps":       c.get("capability.issued", 0),
        "promoted":   c.get("terrain.access_changed", 0),
        "edges":      c.get("attack.edge_added", 0),
        "nodes":      c.get("terrain.node_added", 0),
    }

    findings = []
    fj = run / "findings.jsonl"
    if fj.exists():
        for ln in fj.read_text().splitlines():
            try:
                f = json.loads(ln)
            except Exception:
                continue
            findings.append({"class": f.get("vuln_class", "?"),
                             "sev": f.get("severity", "?"),
                             "label": f.get("label", "")})

    st = _seam(run, "status")
    denied_gates = []
    for ln in st.splitlines():
        low = ln.lower()
        if "blocked" in low or "denied gate" in low:
            txt = ln.strip().lstrip("-").strip()
            if txt and "denied gates" not in low[:14]:
                denied_gates.append(txt)
            elif ":" in ln:  # "denied gates (1): <reason>"
                denied_gates.append(ln.split(":", 1)[1].strip())

    lane = ""
    lf = run / "current_lane"
    if lf.exists():
        lane = lf.read_text().strip()[:40]

    return {
        "generation": int(time.time()),
        "running": bool(running),
        "lane": lane,
        "counts": counts,
        "findings": findings,
        "denied_gates": denied_gates,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--running", action="store_true")
    ap.add_argument("--out", action="append", required=True)
    a = ap.parse_args()
    data = build(Path(a.run_dir), a.running)
    for out in a.out:
        Path(out).write_text(json.dumps(data, indent=2))
    print(f"manager.json: dispatched={data['counts']['dispatched']} verified={data['counts']['verified']} "
          f"denied={data['counts']['denied']} findings={len(data['findings'])} running={data['running']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
