#!/usr/bin/env python3
"""recon_advisor — the MANAGER's continuous "where do I spend energy next?" oracle
(WS-B, gunbelt-16/17). This is the centerpiece Ben pointed at: Ariadne should be used
every cycle to allocate effort, and today it isn't (`/recon` had ZERO callers).

It reads autoturret's grounded state, feeds Ariadne a RICH fact-graph (via ariadne_translate,
WS-A), runs a GOAL LADDER through /plan AND the forward frontier through /recon, and returns
the Ariadne half of the shared advisory contract (gunbelt-17):

    {"stamp":      {facts_n, corpus_hash, ts},
     "goals":      [{goal, status: grounded|near|needs_recon,
                     assumptions, path:[op...], unblocks_n, goal_term}],
     "recon_next": [{confirm, unblocks_goal, gain}]}

manager_bridge merges BS2's `troopers[]` + posture `gate` into the single `advisory` field.
Ariadne half is POSTURE-BLIND — pure logic; all gating is BS2's layer over this raw output.

Content-blind, fail-soft: any Ariadne error yields an empty-but-valid advisory with a
`stamp.error`, never an exception — the manager must never treat a degraded planner as
"nothing to do here."

The GOAL LADDER (join keys are these exact literal strings — BS2 keys troopers[].goal to them):
    foothold  read_file  rce_as  have_cred  controls_principal  pwn_host
`foothold` and `rce_as` are distinct rungs though both underlie rce_as(): foothold = first
code-exec as the web user, rce_as = escalation to root. The concrete Ariadne pattern rides in
`goal_term` (which the join can ignore).
"""
from __future__ import annotations
import os, json, time, urllib.request

import ariadne_translate as AT

ARIADNE = os.environ.get("GB_ARIADNE", "http://127.0.0.1:8112")

# rung label (the join key) -> builder(state) -> concrete Ariadne goal pattern
def _web_user(apps):
    for a in ("gitlab", "wordpress", "drupal", "osticket", "joomla", "tomcat"):
        if a in (apps or {}):
            return AT.DEF_USER.get(a, "www-data")
    return "www-data"

LADDER = [
    ("foothold",           lambda s: ["rce_as", _web_user(s.get("apps"))]),
    ("read_file",          lambda s: ["read_file", os.environ.get("GB_LOOT_FILE", "/root/root.txt")]),
    ("rce_as",             lambda s: ["rce_as", "root"]),
    ("have_cred",          lambda s: ["have_cred", "?c"]),
    ("controls_principal", lambda s: ["controls_principal", "domain_admin"]),
    ("pwn_host",           lambda s: ["pwn_host", os.environ.get("GB_DC", "dc")]),
]


def _post(path, body, timeout=6):
    try:
        req = urllib.request.Request(ARIADNE.rstrip("/") + path,
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {"error": str(e)}


def _classify(plan_resp):
    """(/plan response) -> (status, best_path_step_names, best_assumptions). Best = the path the
    server already ranked first (fewest assumptions, shortest, cheapest)."""
    if plan_resp.get("error"):
        return "needs_recon", [], []
    paths = plan_resp.get("paths") or []
    if not paths:
        return "needs_recon", [], []
    grounded = [p for p in paths if not (p.get("assumptions"))]
    if grounded:
        best = grounded[0]
        return "grounded", [s["name"] for s in (best.get("steps") or [])], []
    best = paths[0]  # all relaxed; server already sorted fewest-assumption first
    return "near", [s["name"] for s in (best.get("steps") or [])], \
        [list(a) for a in (best.get("assumptions") or [])]


def advise_from_state(proven, apps, negatives=None, exploits_fn=None, host=None,
                      recon_for=2, top=3, extra_facts=None):
    """Engine grounded state -> the Ariadne half of the advisory. `recon_for` bounds how many
    non-grounded rungs we spend a /recon call on (cheapest-first, keeps latency bounded).
    `extra_facts` = already-valid Ariadne facts (e.g. web-surface facts from the mapper) merged
    into the graph verbatim."""
    negatives = [list(n) for n in (negatives or [])]
    exploits_fn = exploits_fn if exploits_fn is not None else (lambda p: AT.exploits_via_http(p, ARIADNE))
    tr = AT.translate_state(proven, apps, exploits_fn=exploits_fn, host=host)
    facts = tr["facts"]
    for f in (extra_facts or []):                    # surface facts (WS-A/C feed)
        lf = [str(x) for x in f]
        if lf not in facts:
            facts.append(lf)

    stamp = {"facts_n": len(facts), "corpus_hash": None, "ts": int(time.time())}
    state = {"apps": apps or {}, "proven": proven or []}
    goals, recon_next = [], []
    recon_spent = 0

    for label, build in LADDER:
        goal_term = build(state)
        resp = _post("/plan", {"graph": {"goal": goal_term, "facts": facts,
                                          "negatives": negatives}, "top": top})
        if stamp["corpus_hash"] is None and resp.get("corpus_hash"):
            stamp["corpus_hash"] = resp["corpus_hash"]
        status, path, assumptions = _classify(resp)
        unblocks_n = 0 if status == "grounded" and not path else len(assumptions) if status == "near" else len(path)
        goals.append({"goal": label, "status": status, "assumptions": assumptions,
                      "path": path, "unblocks_n": unblocks_n, "goal_term": goal_term})

        # forward frontier: for the cheapest unmet rungs, ask Ariadne what to CONFIRM next
        if status != "grounded" and recon_spent < recon_for:
            recon_spent += 1
            r = _post("/recon", {"graph": {"goal": goal_term, "facts": facts,
                                           "negatives": negatives}})
            for row in (r.get("confirm_next") or []):
                recon_next.append({"confirm": row.get("fact"), "unblocks_goal": label,
                                   "gain": int(row.get("unblocks", 0) or 0)})

    # dedup recon targets by the confirmed fact, keeping the highest-gain occurrence
    dedup = {}
    for row in recon_next:
        k = json.dumps(row["confirm"])
        if k not in dedup or row["gain"] > dedup[k]["gain"]:
            dedup[k] = row
    recon_next = sorted(dedup.values(), key=lambda x: -x["gain"])

    if stamp["corpus_hash"] is None:
        stamp["error"] = "ariadne unreachable — advisory is empty, NOT 'nothing to do'"
    return {"stamp": stamp, "goals": goals, "recon_next": recon_next}


def _load_surface_facts(run_dir):
    """Web-surface ground facts from web_surface_mapper's ariadne_facts.jsonl (endpoint / tool /
    injectable / serves_file_by_param / accepts_role_field / reset_flow ...). These are what the
    front-facing web operators (BOLA/BFLA/XSS/...) and BS2's trooper join need — recon.json only
    carries APP-level facts. Best-effort: missing file -> []. Looks in run_dir and a sibling
    engagements/* dir for the freshest map."""
    import glob
    cands = [os.path.join(run_dir, "ariadne_facts.jsonl")]
    cands += sorted(glob.glob(os.path.join(run_dir, "**", "ariadne_facts.jsonl"), recursive=True))
    facts = []
    seen = set()
    for p in cands:
        if not os.path.exists(p):
            continue
        try:
            for line in open(p):
                line = line.strip()
                if not line:
                    continue
                f = json.loads(line)
                if isinstance(f, list) and f:
                    k = json.dumps(f)
                    if k not in seen:
                        seen.add(k)
                        facts.append(f)
        except Exception:
            continue
    return facts


def advise_from_recon_json(path, surface_dir=None):
    """Read an autoturret recon.json ({proven_facts|proven, apps, negatives?}) and advise.
    This is the live integration point manager_bridge calls. Merges, when present:
      * sidecar negatives.json (proof-gated fold, WS-E) — provenance-stamped hard prunes
      * ariadne_facts.jsonl (web surface, WS-A/C) — endpoint-level observables
    so the oracle sees app facts + web surface + confirmed-dead branches together."""
    run_dir = os.path.dirname(os.path.abspath(path))
    try:
        d = json.load(open(path))
    except Exception:
        # No recon.json (e.g. a web-surface-only engagement): advise from the
        # discovered surface facts alone rather than returning empty.
        surface = _load_surface_facts(surface_dir or run_dir)
        if surface:
            return advise_from_state([], {}, negatives=[], extra_facts=surface)
        return {"stamp": {"facts_n": 0, "corpus_hash": None, "ts": int(time.time()),
                          "error": "no recon.json and no surface facts"}, "goals": [], "recon_next": []}
    proven = d.get("proven_facts") or d.get("proven") or []

    # negatives: recon.json field (legacy) + sidecar (WS-E, provenance-aware)
    negatives = [list(n) for n in (d.get("negatives") or [])]
    try:
        import planner_negatives as PN
        for f in PN.facts(run_dir):
            if list(f) not in negatives:
                negatives.append(list(f))
    except Exception:
        pass

    # web surface facts join straight into the graph as pre-validated ground facts
    surface = _load_surface_facts(surface_dir or run_dir)

    return advise_from_state(proven, d.get("apps") or {}, negatives=negatives,
                             host=d.get("target"), extra_facts=surface)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Ariadne energy-allocation advisory")
    ap.add_argument("--recon", help="path to an autoturret recon.json")
    ap.add_argument("--state", help="JSON {proven:[...], apps:{...}}")
    ap.add_argument("--offline", action="store_true", help="skip /exploits arming")
    a = ap.parse_args()
    if a.recon:
        adv = advise_from_recon_json(a.recon)
    else:
        if a.state:
            st = json.load(open(a.state))
        else:
            st = {"apps": {"gitlab": "13.10.1"},
                  "proven": [{"fact": "app_gitlab"}, {"fact": "shell=git"},
                             {"fact": "cred=tom:charlie1"}]}
        exf = (lambda p: []) if a.offline else None
        adv = advise_from_state(st.get("proven"), st.get("apps"), exploits_fn=exf)
    print(json.dumps(adv, indent=2))
    g = adv["goals"]
    print(f"\n# stamp: {adv['stamp']}")
    print("# " + "  ".join(f"{x['goal']}:{x['status']}" for x in g))
    print(f"# {len(adv['recon_next'])} recon targets"
          + (f" — top: confirm {adv['recon_next'][0]['confirm']} (gain {adv['recon_next'][0]['gain']})"
             if adv['recon_next'] else ""))
