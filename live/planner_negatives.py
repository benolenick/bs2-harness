#!/usr/bin/env python3
"""planner_negatives — proof-gated negative fold with provenance (WS-E, gunbelt-16/17).

WHY: plan_and_fire builds `negatives` in a LOCAL list and drops them when it returns, so a
branch proven dead this cycle is re-attempted next cycle, and the recon_advisor oracle can't
see it. This module persists negatives so Ariadne hard-prunes dead branches across cycles —
WITHOUT the two failure modes om-b9 flagged:

  (a) NO two-writer race on recon.json. Negatives live in a SIDECAR file
      `negatives.json`, written atomically (tmp + os.replace), owned solely by the planner.
      recon.json's existing writer is never touched. recon_advisor merges both sources.
  (b) NO immortal negatives. Each negative carries provenance {op, cycle, ts}. When a new
      capability appears that could deliver a negated fact, `retract_recoverable()` removes
      the stale prune so the branch can be re-planned.

Content-blind: negatives are fact KEYS/patterns (e.g. ["rce_as","www-data"]), never output.

API:
    fold_negative(negs, fact, op, cycle)        -> append {fact, op, cycle, ts} if new
    stage(run_dir, negs)                        -> atomic write to <run_dir>/negatives.json
    load(run_dir)                               -> [ {fact, op, cycle, ts}, ... ]
    facts(run_dir)                              -> [ [pred,...], ... ]  (bare facts for /plan)
    retract_recoverable(run_dir, new_capabilities) -> int removed
"""
from __future__ import annotations
import json, os, time

SIDECAR = "negatives.json"


def _now() -> int:
    return int(time.time())


def fold_negative(negs: list, fact, op: str = "", cycle: int = 0) -> list:
    """Append a provenance-stamped negative if that fact isn't already present. `negs` is a
    list of {fact, op, cycle, ts}. Returns the same list (mutated) for chaining."""
    if fact is None:
        return negs
    fact = [str(x) for x in fact]
    if any(n.get("fact") == fact for n in negs):
        return negs
    negs.append({"fact": fact, "op": str(op), "cycle": int(cycle), "ts": _now()})
    return negs


def load(run_dir: str) -> list:
    """Provenance records from the sidecar. Tolerates: absent file, a bare list-of-facts
    (old shape), or the record shape — always returns record dicts."""
    path = os.path.join(run_dir, SIDECAR)
    try:
        raw = json.load(open(path))
    except Exception:
        return []
    out = []
    for item in (raw if isinstance(raw, list) else raw.get("negatives", [])):
        if isinstance(item, dict) and "fact" in item:
            out.append({"fact": [str(x) for x in item["fact"]],
                        "op": item.get("op", ""), "cycle": int(item.get("cycle", 0)),
                        "ts": int(item.get("ts", 0))})
        elif isinstance(item, list):                      # bare fact -> wrap
            out.append({"fact": [str(x) for x in item], "op": "", "cycle": 0, "ts": 0})
    return out


def facts(run_dir: str) -> list:
    """Just the negated fact patterns, for feeding a /plan or /recon graph."""
    return [n["fact"] for n in load(run_dir)]


def stage(run_dir: str, negs: list) -> str:
    """Atomically MERGE `negs` (list of records OR bare facts) into the sidecar. tmp+os.replace
    like the rest of atrun, so a reader never sees a half-written file. Returns the path."""
    existing = load(run_dir)
    seen = {json.dumps(n["fact"]) for n in existing}
    for item in negs or []:
        rec = item if isinstance(item, dict) and "fact" in item else {
            "fact": [str(x) for x in item], "op": "", "cycle": 0, "ts": _now()}
        k = json.dumps([str(x) for x in rec["fact"]])
        if k not in seen:
            seen.add(k)
            existing.append({"fact": [str(x) for x in rec["fact"]], "op": rec.get("op", ""),
                             "cycle": int(rec.get("cycle", 0)), "ts": int(rec.get("ts", _now()))})
    path = os.path.join(run_dir, SIDECAR)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(existing, f, indent=2)
    os.replace(tmp, path)
    return path


def retract_recoverable(run_dir: str, new_capabilities) -> int:
    """Remove negatives that a newly-gained capability could now deliver, so a stale prune
    never kills a branch forever. `new_capabilities` is a set/list of predicate names we can
    now produce (e.g. {"rce_as"} after a fresh exploit lane armed). A negative whose fact's
    predicate is in that set is retracted. Returns count removed."""
    caps = {str(c) for c in (new_capabilities or [])}
    if not caps:
        return 0
    recs = load(run_dir)
    keep = [n for n in recs if n["fact"] and n["fact"][0] not in caps]
    removed = len(recs) - len(keep)
    if removed:
        path = os.path.join(run_dir, SIDECAR)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(keep, f, indent=2)
        os.replace(tmp, path)
    return removed


if __name__ == "__main__":
    import argparse, tempfile
    ap = argparse.ArgumentParser(description="planner negative sidecar")
    ap.add_argument("cmd", choices=["show", "selftest"])
    ap.add_argument("--run", default=".")
    a = ap.parse_args()
    if a.cmd == "show":
        for n in load(a.run):
            print(json.dumps(n))
    else:
        d = tempfile.mkdtemp()
        negs = []
        fold_negative(negs, ["rce_as", "www-data"], "run-public-exploit", 1)
        fold_negative(negs, ["rce_as", "www-data"], "ssti-rce", 2)          # dup fact -> ignored
        fold_negative(negs, ["read_file", "/root/root.txt"], "lfi", 2)
        assert len(negs) == 2, negs
        stage(d, negs)
        stage(d, [["db_read", "/api/x"]])                                    # bare fact merge
        assert len(load(d)) == 3, load(d)
        assert ["rce_as", "www-data"] in facts(d)
        r = retract_recoverable(d, {"rce_as"})                               # new exploit lane
        assert r == 1 and ["rce_as", "www-data"] not in facts(d), (r, facts(d))
        assert len(load(d)) == 2
        print("selftest OK — fold dedups, stage merges atomically, retract lifts stale prune")
