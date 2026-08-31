#!/usr/bin/env python3
"""autoturret_planner — the goal->Ariadne-plan->fire->negative-prune loop (see NORTH-STAR.md).

Turns autoturret from a STATIC belt into terrain-driven attack:
  translate grounded floor-facts into Ariadne's vocabulary -> set an attainable goal ->
  /plan a PATH of operators -> fire weapon-or-trooper for the next operator -> ground ->
  advance (add fact) or PRUNE (add negative, Ariadne kills the branch) -> re-plan.

Content-blind: the planner reasons over fact KEYS + operator names, never raw exploit output.
Ariadne is fragile (SIGIL) — every call is best-effort and NEVER blocks the loop.
"""
import json, os, re, urllib.request, urllib.parse
import planner_negatives as _PN
from autoturret import RUN_DIR                      # module-global atrun dir (gunbelt-18 fold)

_AR_RAW = os.environ.get("GB_ARIADNE", "").strip()
# GB_ARIADNE is overloaded: bench arms use it as an on/off toggle, this client needs a URL.
# Treat toggle-ish values as "use the default service URL" so the two semantics don't collide.
ARIADNE = _AR_RAW if _AR_RAW.startswith("http") else "http://127.0.0.1:8112"
_PRED_PATH = "/home/operator/ariadne/ariadne/corpus/predicates.yaml"

def _load_predicates():
    try:
        import yaml
        d = yaml.safe_load(open(_PRED_PATH))
        return {p["name"]: p["arity"] for p in d.get("predicates", [])}
    except Exception:
        # minimal fallback vocab (the ones our translation emits) if the file/yaml is unavailable
        return {"vuln_present": 2, "known_exploit": 2, "runs_as": 2, "rce_as": 1, "read_file": 1,
                "have_cred": 1, "cred_reused_on": 2, "crackable_hash": 1, "can_read": 2,
                "suid_binary": 2, "can_sudo": 2, "gtfobin": 3, "pwn_host": 1, "controls_principal": 1}
PREDS = _load_predicates()

def _valid(fact):
    return fact[0] in PREDS and PREDS[fact[0]] == len(fact) - 1

def _safe(s):
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", str(s))[:60]


def _post(path, body, timeout=6):
    try:
        req = urllib.request.Request(ARIADNE.rstrip("/") + path,
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {"error": str(e)}

def exploits(prod, n=3):
    """[(prod, cve_or_edb)] version-matched leads from Ariadne's exploit index. Best-effort."""
    try:
        with urllib.request.urlopen(ARIADNE.rstrip("/") + "/exploits?q=" + urllib.parse.quote(prod),
                                    timeout=5) as r:
            data = json.load(r)
    except Exception:
        return []
    out = []
    for m in (data.get("matches") or [])[:n]:
        cve = (m.get("cves") or [None])[0] or ("EDB-" + str(m.get("edb")))
        out.append((prod, cve))
    return out


# our-fact-vocab -> Ariadne-predicate-vocab (the keystone join)
DEF_USER = {"gitlab": "git", "wordpress": "www-data", "drupal": "www-data", "osticket": "www-data"}

def translate(proven_facts, apps):
    """Grounded floor facts + fingerprinted apps -> a list of VALID Ariadne facts (dropped if a
    predicate is out-of-vocab, so one bad fact never dead-ends /plan)."""
    facts, dropped = [], []
    def add(f):
        (facts if _valid(f) else dropped).append(f)
    seen = {p["fact"].split("=", 1)[0] + "=" + p["fact"].split("=", 1)[1] if "=" in p["fact"] else p["fact"]
            for p in proven_facts}
    # app fingerprints -> vuln_present + known_exploit (+ assumed runs_as, confirmed on foothold)
    for app, host in (apps or {}).items():
        h = _safe(host or app)
        add(["vuln_present", h, app])
        add(["runs_as", h, DEF_USER.get(app, "www-data")])
        for prod, cve in exploits(app):
            add(["known_exploit", app, _safe(cve)])
    # compromise facts already grounded by the engine
    for p in proven_facts:
        f = p["fact"]
        key, _, val = f.partition("=")
        if key == "shell" and val:
            add(["rce_as", _safe(val)])
        elif key == "cred" and val:
            add(["have_cred", _safe(val)])
        elif key == "hash" and val:
            add(["crackable_hash", _safe(val)[:20]])
    # de-dup
    uniq = []
    for f in facts:
        if f not in uniq:
            uniq.append(f)
    return uniq, dropped


# Ariadne operator -> how autoturret fires it. Known operators fast-path to a belt lane id;
# anything else falls to the trooper with the operator's description as the objective.
OP_TO_LANE = {
    "run-public-exploit": {"gitlab": "gitlab-cve", "wordpress": "wp-lfi", "drupal": "drupal-chk"},
    "os-rce-file-read": "loot-foothold",
    "gtfobin-suid-shell": "privesc", "gtfobin-sudo-shell": "privesc",
    "gtfobin-suid-fileread": "privesc", "gtfobin-sudo-fileread": "privesc",
    "cred-reuse-login": "own-dc",
}

def _filter_facts(facts):
    """Keep only schema-valid facts; a single unknown-predicate/arity fact makes the
    planner 400 the whole request. Callers fold rich engine facts (vhost=, shell=, ...)
    that aren't in the AD PREDS schema, so filter defensively before POSTing."""
    out = []
    for f in (facts or []):
        try:
            ff = list(f)
            if ff and ff[0] in PREDS and PREDS[ff[0]] == len(ff) - 1:
                out.append(ff)
        except Exception:
            continue
    return out

def plan(goal, facts, negatives, top=3):
    return _post("/plan", {"graph": {"goal": goal, "facts": _filter_facts(facts),
                                     "negatives": _filter_facts(negatives)}, "top": top})

def recon(goal, facts, negatives):
    return _post("/recon", {"graph": {"goal": goal, "facts": facts, "negatives": negatives}})


# canonical POST fact per operator (for negative-pruning when an operator can't deliver).
# Keyed to the goal/app context. Pruning a post kills that branch so Ariadne re-plans a different one.
def _op_post(op, goal, app_user):
    if op == "run-public-exploit":       return ["rce_as", app_user]
    if op in ("ssti-rce", "command-injection-rce", "deserialization-rce", "gadget-prototype-rce"):
        return ["rce_as", app_user]
    if op in ("gtfobin-suid-shell", "gtfobin-sudo-shell"):  return ["rce_as", "root"]
    if op == "cred-reuse-login":         return ["rce_as", app_user]
    if op in ("os-rce-file-read", "lfi-path-traversal", "ssti-file-read") and goal[0] == "read_file":
        return list(goal)
    return None


def _resolve(op, engine, app):
    """Ariadne operator -> (belt lane dict, fact-key that proves it). None lane => can't fire it."""
    tgt = OP_TO_LANE.get(op)
    lane_id = tgt.get(app) if isinstance(tgt, dict) else tgt
    key = {"run-public-exploit": "shell", "gtfobin-suid-shell": "shell", "gtfobin-sudo-shell": "shell",
           "os-rce-file-read": "flag", "cred-reuse-login": "dc_cred"}.get(op, "shell")
    if lane_id:
        for l in getattr(engine, "_all_lanes", None) or engine.belt:
            if l["id"] == lane_id:
                return l, key
    return None, key


def plan_and_fire(engine, goal, emit, max_steps=8):
    """The goal->plan->fire->prune loop. `engine` is an Autoturret (reuses its fire/apply/facts);
    `emit` is engine.emit. Returns the final plan status dict."""
    app = next((a for a in ("gitlab", "wordpress", "drupal", "osticket") if a in engine.apps), "")
    app_user = DEF_USER.get(app, "www-data")
    neg_records = _PN.load(RUN_DIR)                 # resume prior cycles' prunes (sidecar)
    negatives = [n["fact"] for n in neg_records]     # what /plan consumes (unchanged downstream)
    emit("sys", "planner", f"PLANNER online — goal {goal}, app={app or 'none'}", "", "plan")
    for step in range(max_steps):
        facts, dropped = translate(engine.proven, engine.apps)
        try:                                        # Q3: once-per-cycle energy log — read-only, never gates a fire
            import recon_advisor as _RA
            _adv = _RA.advise_from_state(engine.proven, engine.apps, negatives=negatives)
            emit("plan", "planner", "energy: " + "  ".join(
                f"{g['goal']}:{g['status']}" for g in _adv["goals"])
                + (f" | next: confirm {_adv['recon_next'][0]['confirm']}"
                   f" (gain {_adv['recon_next'][0]['gain']})" if _adv["recon_next"] else ""),
                "", "plan")
        except Exception:
            pass                                    # advisory is never allowed to break the fire loop
        p = plan(goal, facts, negatives)
        if p.get("error"):
            emit("plan", "planner", f"ariadne error: {p['error'][:80]} — planner halts", "", "plan"); break
        paths = p.get("paths") or []
        if not paths:
            emit("plan", "planner", "no path to goal — pruned dry (genuinely out of ideas)", "", "plan"); break
        top = paths[0]; steps = top.get("steps") or []
        if not steps:                                 # goal already satisfied by current facts
            emit("plan", "planner", f"✔ goal {goal} GROUNDED", "", "plan"); return {"grounded": True, "goal": goal}
        op = steps[0]["name"]
        emit("plan", "planner", f"↳ path [{', '.join(s['name'] for s in steps)}] — firing {op}"
             f"{' (relaxed:'+str(top.get('assumptions'))+')' if top.get('assumptions') else ''}", "", "plan")
        lane, key = _resolve(op, engine, app)
        fired = lane is not None and lane["id"] not in engine.started
        if fired:
            engine.started.add(lane["id"])
            _, v = engine.fire(lane)
            engine.apply(lane, v)
        # did the operator deliver a GROUNDED post?
        if key in engine.facts:
            emit("plan", "planner", f"✔ {op} delivered {key} (grounded) — replanning from new facts", "", "plan")
            continue                                  # re-plan: path shrinks toward the goal
        # couldn't fire (no lane / already tried) or fired-but-ungrounded -> PRUNE the branch
        neg = _op_post(op, goal, app_user)
        if neg and neg not in negatives:
            negatives.append(neg)
            _PN.fold_negative(neg_records, neg, op=op, cycle=step)   # provenance-stamped sidecar record
            emit("plan", "planner", f"⊘ {op} did not deliver — negative {neg}, Ariadne prunes + re-plans", "", "plan")
        else:
            emit("plan", "planner", f"⊘ {op} unfireable and unprunable — planner halts", "", "plan"); break
    _PN.stage(RUN_DIR, neg_records)                 # atomic sidecar flush -> <RUN_DIR>/negatives.json
    return {"grounded": key in engine.facts, "goal": goal, "negatives": negatives}
