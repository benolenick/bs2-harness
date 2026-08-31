#!/usr/bin/env python3
"""Deep crAPI pentest driver — MANAGER-IN-THE-LOOP under the full BS2 governance spine.

NORTH STAR (see HOW_I_BROKE_BATTLESTATION_AND_HOW_IT_SHOULD_WORK.md): each lane is run by
manager_loop.run_manager_lane, where the MANAGER (Opus, content-blind, `claude -p`) is FED a
live picture — the surface MAP (worklist endpoints), Ariadne's PROPOSED ROUTES (adv["goals"]),
and Memoria RECALL (memoria_enrich) — and from that AUTHORS one concrete next action per turn.
The DeepSeek trooper is a pure TRIGGER: it fires the authored command and returns only a
SANITIZED marker (a status code / a scrubbed id / a yes-no bit). There is NO frozen
`if <vuln-shape>:` strategy in this driver — the thinking lives in the manager, per the north
star. (The prior version's `run_microsteps` hardcoded the attack decisions; it was removed.)

This driver is FEED + FIRE + GOVERNANCE plumbing only. It consumes ONLY scrubbed facts[] +
telemetry (keys, never values) and NEVER reads raw command output.

It keeps the three governance fixes Ben approved ("wire that"):

  #1 ITERATIVE REPLAN     build_advisory() re-runs every iteration over the CURRENT
                          worklist + grounded ariadne_facts + negatives, so Ariadne's
                          goal ladder and the trooper ranking shift as facts ground.
                          (Last run advisory was computed once; now it drives the loop.)

  #2 HOUSEKEEPING LOAD-BEARING  every dispatch decision is routed
                          enter_focus -> record_decision -> checkpoint -> close_focus
                          through the SIGIL HousekeepingController over the gunbelt
                          .sigil topology. If the choke-point REJECTS a dispatch
                          (undeclared route / mission drift) the driver records it and
                          skips the lane -- SIGIL is authoritative, not decorative.

  #3 MEASURED-POSTURE RECEIPT   an exploit.* lane under measured posture mints a
                          governed approval receipt before dispatch (the ROE path that
                          never fired last run because every class was PASSIVE/ACTIVE).
"""
import json, os, sys, time, shutil, subprocess, copy

# ---- paths -----------------------------------------------------------------
MANAGER = "/opt/bs2/manager"
LIVE    = "/opt/bs2/live"
LAB     = "/mnt/sata/sigil-runtime-lab"
BSTN    = "/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2"
SIGIL   = "/opt/bs2/.sigil"
SRC     = os.environ.get("GB_SRC", "/opt/bs2/bench/seed/crapi")
RUN_DIR = os.environ.get("GB_RUN_DIR", "/tmp/claude-1000/-home-om/1116dd00-f15e-41ca-bb36-1432e08397fc/scratchpad/crapi-ds")
os.makedirs(RUN_DIR, exist_ok=True)
TARGET  = "http://127.0.0.1:8888"
POSTURE = "measured"
ITER_CAP = int(os.environ.get("ITER_CAP", "8"))

for p in (MANAGER, LIVE, LAB, BSTN, f"{BSTN}/battlestation"):
    if p not in sys.path: sys.path.insert(0, p)

# ---- DeepSeek trooper env (set BEFORE importing trooper) --------------------
os.environ["TROOPER_BASE"]       = os.environ.get("GB_TROOPER_BASE", "https://api.deepseek.com")
os.environ["TROOPER_MODEL"]      = os.environ.get("DS_MODEL", "deepseek-v4-flash")
os.environ["TROOPER_KEY_FILE"]   = os.environ.get("GB_TROOPER_KEY_FILE", "/opt/bs2/.ds_key")
os.environ["GB_ALLOW_LOOPBACK"]  = "1"          # target is authorized loopback (crAPI :8888)
os.environ["GB_CHARTER_PORTS"]   = "8888"       # charter ports ride to the trooper (pass-4 lesson)
os.environ["TROOPER_MAX_TURNS"]  = os.environ.get("TROOPER_MAX_TURNS", "12")
os.environ["TROOPER_CMD_TIMEOUT"]= "40"

import manager_bridge as MB
import trooper as TR
import troopers as TP           # battlestation troopers (advisory_from_worklist)
import manager_loop as ML       # NORTH-STAR manager-in-the-loop lane runner
from lenz_harness import SafeLenzStream
sys.path.insert(0, LIVE)
try:
    import memoria_enrich as MEM   # corpus recall feed (fails soft to "")
except Exception:
    MEM = None

# ---- scrubbed run-log (the ONLY thing the manager reads) -------------------
LOG = []
LENZ = None
def log(kind, **kw):
    row = {"t": int(time.time()), "kind": kind, **kw}
    LOG.append(row)
    # console line is fact-KEYS only, never values
    print(f"[{kind}] " + " ".join(f"{k}={v}" for k, v in kw.items() if k != "output")[:300], flush=True)
    if LENZ is not None:
        if kind == "microstep" and kw.get("manager_verb"):
            LENZ.manager(int(kw.get("step", 0)), kw["manager_verb"],
                         int(kw.get("routes_n", 0)), bool(kw.get("memoria", False)))
        elif kind == "trooper_result":
            LENZ.ran(int(kw.get("iter", 0)), int(kw.get("secs", 0)),
                     int(kw.get("cmds", 0)), bool(kw.get("blocked")))
        elif kind == "finding_verified":
            LENZ.finding(int(kw.get("iter", 0)), bool(kw.get("verified")))
        if kind == "advisory":
            pass
        elif kind == "dispatch":
            LENZ.translate(int(kw.get("iter", 0)), "feed", "feed_update",
                int(kw.get("endpoints", 0)), int(kw.get("routes", 0)),
                "memory_available" if kw.get("memoria") else "memory_unavailable")
        elif kind == "microstep":
            _verb = str(kw.get("manager_verb", "INVALID")).lower()
            LENZ.translate(int(kw.get("step", 0)), "manager", "manager_action",
                           status=_verb if _verb in {"run", "finding", "done", "invalid"} else "invalid")
        elif kind == "trooper_result":
            _status = "success" if kw.get("success") else ("blocked" if kw.get("blocked") else "no_signal")
            LENZ.translate(int(kw.get("iter", 0)), "hands", "hands_result",
                           int(kw.get("cmds", 0)), 0, _status)
        elif kind == "final":
            LENZ.translate(int(kw.get("dispatched", 0)), "system", "run_finished",
                           int(kw.get("dispatched", 0)), int(kw.get("solved", 0)), "stopped")
            LENZ.stop(int(kw.get("dispatched", 0)))
        elif kind in {"lane_error", "abort"}:
            LENZ.translate(int(kw.get("iter", 0) or 0), "system", "run_finished", status="error")
def flush_log():
    json.dump(LOG, open(f"{RUN_DIR}/run_log.json", "w"), indent=1)

def gseam(*args):
    """governed_seam CLI; returns parsed JSON (best-effort)."""
    r = subprocess.run(["python3", f"{LIVE}/governed_seam.py", *args],
                       capture_output=True, text=True, timeout=60)
    for cand in (r.stdout.strip(), r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""):
        try: return json.loads(cand)
        except Exception: continue
    return {"raw_rc": r.returncode, "err": (r.stderr or r.stdout)[:200]}

# ---- fix #3: posture receipt gate ------------------------------------------
CLASS_ACTION = {"sqli": "exploit.sqli", "nosqli": "exploit.nosqli",
                "broken-access-control": "exploit.bola", "bola": "exploit.bola",
                "auth-bypass": "exploit.authbypass", "jwt": "exploit.jwt",
                "xss": "exploit.xss", "path-traversal": "exploit.lfi", "lfi": "exploit.lfi"}
def _measured_needs_receipt(action):
    # measured posture gates exploit.* creds.brute creds.spray dos.* persist.* lateral.*
    import re
    for pat in ("exploit\\..*", "creds\\.brute", "creds\\.spray", "dos\\..*",
                "persist\\..*", "lateral\\..*"):
        if re.fullmatch(pat, action): return True
    return False

# ---- fix #2: build the gunbelt SIGIL brain snapshot ------------------------
def build_housekeeping():
    from runtime.brain import BrainClaim, BrainHook, BrainRoute, BrainSnapshot
    from runtime.common import sha256_file
    from runtime.reframe import PhaseEvent, PhaseLedger
    from runtime.housekeeping import HousekeepingController
    root = f"{SIGIL}"
    from pathlib import Path
    # fresh run == fresh focus ledger; a persisted ledger would collide event-ids
    if os.path.isdir(f"{root}/housekeeping"): shutil.rmtree(f"{root}/housekeeping")
    os.makedirs(f"{root}/housekeeping", exist_ok=True)
    ph_path = f"{root}/phases.jsonl"
    if os.path.exists(ph_path): os.remove(ph_path)
    ledger = PhaseLedger(Path(ph_path))
    goal_txt = "Assess crAPI: ground exploit-class findings under measured ROE."
    ledger.append(PhaseEvent.from_mapping({
        "event_id": "phase-start", "sequence": 1, "at": "2026-08-24T17:00:00Z",
        "phase_id": "crapi-deep-1", "topic_key": "crapi-assessment", "status": "active",
        "summary": goal_txt, "goal": goal_txt,
        "frontier": "Rank reachable exploit lanes and confirm the top one.",
        "next_attack": "Dispatch the top-ranked trooper lane and ground its facts.",
        "source": "manager/run_deep_deepseek", "evidence_event_ids": [], "confidence": 5}))
    frame = ledger.current_frame()
    # routes = the 8 gunbelt topology nodes (dispatch must declare a declared route)
    nodes = ["governance", "manager", "ariadne", "autoturret", "gunbelt",
             "troopers", "intelligence", "battle"]
    routes = tuple(BrainRoute(n, f".sigil/nodes/{n}", f"Owns {n}.",
                              f"read {n} slice", "2026-08-24T17:00:00Z", "a"*64,
                              "SIGIL.md#DOWNSTREAM-MAP") for n in nodes)
    snap = BrainSnapshot.create(
        snapshot_id="brain-crapi-deep-1", project="gunbelt",
        personality=BrainClaim("p1", "personality", "Methodical, honest, content-blind.", "INTENT.md#PERSONALITY"),
        north_star=BrainClaim("n1", "north_star", "Grounded, governed offensive assessment.", "INTENT.md#NORTH-STAR"),
        current_goal=BrainClaim("g1", "goal", goal_txt, "session/events.jsonl"),
        frame=frame,
        constraints=(BrainClaim("c1", "constraint", "Manager is content-blind; troopers are the hands.", "SIGIL.md#DIRECTIVES"),),
        decisions=(), negatives=(), routes=routes,
        hooks=(BrainHook("read_selected_node", "Open the selected sub-SIGIL + deps.",
                         "read scoped files, verify hashes", "SIGIL.md#DIRECTIVES"),),
        source_ledger_sha="b"*64, phase_ledger_sha=sha256_file(Path(ph_path)),
        created_at="2026-08-24T17:01:00Z")
    from pathlib import Path
    return HousekeepingController(Path(root), snap)

# ---- grounding: grounded facts + negatives feed the NEXT advisory ----------
def ground(cls, endpoints, result):
    """Append grounded surface facts + confirmed-negatives so build_advisory shifts.
    Content-blind: consumes result['facts'] (scrubbed keys) only."""
    facts = result.get("facts") or []
    fpath = f"{RUN_DIR}/ariadne_facts.jsonl"
    added = 0
    with open(fpath, "a") as fh:
        for f in facts:
            key = str(f).split("=", 1)[0].lower()
            for ep in endpoints[:6]:
                tup = None
                if cls in ("sqli", "nosqli") and result.get("success"):
                    tup = ["injectable", ep, "sql" if cls == "sqli" else "nosql"]
                elif cls == "broken-access-control" and result.get("success"):
                    tup = ["idor", ep]
                elif "jwt" in key or "alg" in key:
                    tup = ["weak_jwt", ep]
                if tup:
                    fh.write(json.dumps(tup) + "\n"); added += 1
    # confirmed-negative if the lane found nothing
    if not result.get("success"):
        neg = f"{RUN_DIR}/negatives.json"
        cur = []
        try: cur = json.load(open(neg))
        except Exception: pass
        for ep in endpoints[:6]:
            cur.append([cls, ep, "no-signal"])
        json.dump(cur, open(neg, "w"))
    return added

def mark_solved(worklist_path, cls):
    """Remove a solved class from the worklist so the next advisory rescoring
    stops re-picking it (drives the trooper ranking to shift)."""
    rows = json.load(open(worklist_path))
    rows = [r for r in rows if r.get("class") != cls]
    json.dump(rows, open(worklist_path, "w"))
    return len(rows)

# ---- benign harness provisioning: two authed test accounts (NOT exploitation) --
def provision_tokens():
    """Create two test accounts on OUR OWN app and return their bearer tokens so the
    trooper skips the fragile signup handshake and spends its turns on the actual test.
    This is HARNESS SETUP (like provisioning /etc/hosts vhosts), not an attack: it only
    creates accounts and reads the returned session token, never any victim data."""
    import urllib.request
    def _post(path, obj, tries=3):
        for _ in range(tries):
            try:
                return urllib.request.urlopen(urllib.request.Request(
                    f"{TARGET}{path}", json.dumps(obj).encode(),
                    {"Content-Type": "application/json"}), timeout=20).read()
            except Exception:
                time.sleep(2)
        return None
    toks = []
    base = int(time.time())
    for i in (1, 2):
        email = f"pt{i}_{base}{i}@example.com"
        # 10-digit number, leading 9, that stays UNIQUE across i: the old
        # f"9{...:010d}"[:10] truncated the i-varying last digit, so both accounts
        # collided on the same number and crAPI's unique-number constraint dropped
        # the 2nd signup (only 1 token came back -> no cross-owner BOLA possible).
        number = "9" + f"{(base * 10 + i) % 10**9:09d}"    # 10 chars, varies by i
        _post("/identity/api/auth/signup", {"name": f"pentester{i}", "email": email,
              "number": number, "password": "Passw0rd!23"})
        resp = _post("/identity/api/auth/login", {"email": email, "password": "Passw0rd!23"})
        if resp:
            try:
                tok = json.loads(resp).get("token")
                if tok: toks.append((tok, email))          # keep the identity for owner-diff
            except Exception:
                pass
    return toks

# NOTE: the old per-class `lane_objective()` (a frozen "test these for SQLi / swap the id"
# strategy string) was REMOVED in the north-star refactor. The manager now authors every
# objective/command live from the picture (see manager_loop.run_manager_lane). Nothing here
# tells the trooper *what to attack*.

# ---- FIRE primitives (the trooper hands; NO strategy lives here) ------------
# The manager (Opus, in manager_loop) AUTHORS every command from the live picture.
# These functions ONLY execute a manager-authored action and return a SANITIZED
# marker (a status code / a scrubbed id list / a yes-no bit). There is deliberately
# no `if <vuln-shape>:` decision here -- that is the whole point of the refactor.
import re as _re

def _ensure_status_capture(curl):
    """Mechanics only: make sure a manager-authored curl prints just its HTTP status
    code (so the trooper can echo one number). Never changes the URL/headers/method --
    that is the manager's authored strategy, untouched."""
    c = curl.strip()
    if "%{http_code}" not in c:
        c = c.rstrip()
        if " -o " not in c and "--output" not in c:
            c += " -o /dev/null"
        c += " -s -w '%{http_code}'"
    return c

def _fire_probe(cmd, _retry=1):
    """Fire ONE manager-authored command via the trooper; return (status_code|None).
    Tiny turn budget so a weak trooper cannot wander. Retry once on a missing code so a
    flaky None doesn't corrupt the manager's picture (a real reliability bug seen before)."""
    TR.MAX_TURNS = 3
    lane = {"target": TARGET,
            "objective": (f"Run EXACTLY this one command and report the number it prints as a "
                          f"fact ['http_code=<n>']. Then emit VERDICT. Do nothing else.\n{cmd}")}
    for _ in range(_retry + 1):
        r = TR.Trooper().fire(lane)
        for f in (r.get("facts") or []):
            m = _re.search(r"\b(\d{3})\b", str(f))
            if m:
                return int(m.group(1))
    return None

def _fire_listids(cmd):
    """Fire ONE manager-authored curl; the trooper (the hands) may read the JSON body and
    returns up to a few OBJECT IDS it saw -- scrubbed ids only, never PII, never the body.
    The manager stays content-blind: it learns real neighbor ids without seeing anything else."""
    TR.MAX_TURNS = 3
    obj = (f"AUTHORIZED crAPI check. Run this ONE curl. From the JSON response, list up to 6 "
           f"OBJECT ID values you see (numeric ids, uuids, or an `id`/`*_id` field). Emit each as a "
           f"fact ['id=<value>']. Do NOT print names, emails, tokens, or any other field. Then emit "
           f"VERDICT. One curl only:\n{cmd}")
    r = TR.Trooper().fire({"target": TARGET, "objective": obj})
    ids = []
    for f in (r.get("facts") or []):
        m = _re.search(r"id\s*=\s*([A-Za-z0-9:_-]{1,64})", str(f))
        if m and m.group(1).lower() not in ("true", "false", "none"):
            ids.append(m.group(1))
    seen, out = set(), []
    for v in ids:
        if v not in seen:
            seen.add(v); out.append(v)
    return out

def _verify_owner_diff(url, tok, my_email):
    """Delegate ONE content read to the trooper; it returns a single scrubbed BIT. The trooper
    (the hands) sees the body; the manager only learns yes/no. Turns an auth-gated 200 into a
    CONFIRMED cross-owner read -- the manager decides (live) WHEN to call this, not a frozen branch."""
    TR.MAX_TURNS = 3
    obj = (f"AUTHORIZED crAPI check. Fetch this ONE url with the bearer, look at the returned "
           f"object's owner/email/user field. Your identity is '{my_email}'. If the object clearly "
           f"belongs to a DIFFERENT user than you, emit fact ['ownerdiff=yes']; if it is yours or "
           f"you cannot tell, emit ['ownerdiff=no']. Do NOT print or exfiltrate the PII itself. "
           f"Then emit VERDICT. One curl only:\n"
           f"curl -s -m 15 -H 'Authorization: Bearer {tok}' '{url}'")
    r = TR.Trooper().fire({"target": TARGET, "objective": obj})
    for fct in (r.get("facts") or []):
        m = _re.search(r"ownerdiff\s*=\s*(yes|no)", str(fct), _re.I)
        if m: return m.group(1).lower()
    return "unknown"

# ---- deterministic BOLA slice (P1-2 graft, 2026-08-25) ----------------------
# The lab slice (live/bola_slice.py) replaces the LLM ownerdiff bit with a
# deterministic matrix: own ids via the app's OWN list endpoint -> differential
# control/test per principal pair -> ONE bound anon ownership-diff -> candidate.
# Everything below returns SCRUBBED markers only (verdicts + statuses, never
# bodies/tokens/PII); the manager stays content-blind and still authors WHEN to act.
def _template_var(route):
    m = _re.search(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", str(route))
    return m.group(1) if m else "id"

def slice_plan_for(route_template, id_sources=None, method="GET", target=TARGET):
    """Harvested templated endpoint -> a generic slice plan dict. id_sources maps the
    template var to the app's OWN list route that exposes the var's ids (crAPI default:
    vehicles list, uuid field — this DRIVER is crAPI-specific; the library is not)."""
    var = _template_var(route_template)
    return {"target": target,
            "endpoints": [{"id": "ep-bola", "method": method,
                           "route_template": route_template, "template_var": var}],
            "id_sources": id_sources or {"vehicleid": {
                "route_template": "/identity/api/v2/vehicle/vehicles", "field": "uuid"}},
            "principals": []}           # filled by _fire_slice from provisioned tokens

def _slice_principals(tokens, run_dir):
    """Provisioned bearer tokens -> principal REFS for the slice. Tokens land ONLY in
    600 files on this host; the slice's governed curls resolve them on the exec host
    (the door audits cmd_sha, not values) — never argv literals in THIS process, never
    in records or logs. GB_RAW_LOG must stay OFF while authed sessions run."""
    import stat
    out = []
    for i, tok in enumerate(tokens or [], start=1):
        path = os.path.join(run_dir, "tokens", f"p{i}.token")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(tok.strip())
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        out.append({"principal": f"user:pt{i}",
                    "auth": {"token_file": path}, "refs": {}})
    return out

def _fire_slice(plan, tokens=None):
    """Run the slice plan through the GOVERNED seam (the same door the lab slice proves)
    and return scrubbed markers: {"status", "candidates", "rows", "briefs_n", "denied"}.
    Fail-closed: a seam denial or engine error yields denied/error markers, never a
    candidate. Nothing here fires a finding or a mutation — the manager decides."""
    import bola_slice as BS
    import governed_runner as GR
    os.environ["GB_GOVERNED"] = "1"
    os.environ["BS2_SEAM_RUN"] = RUN_DIR
    if not plan.get("principals") and tokens:
        plan = dict(plan, principals=_slice_principals(tokens, RUN_DIR))
    try:
        # ONE ledger per run dir: slice matrices dedup across lane invocations AND
        # across runs (the no-repeat contract every specialist lane shares)
        result = BS.run_slice(plan, GR.make_runner(timeout=30), ledger_dir=RUN_DIR)
    except Exception as e:
        return {"status": "error", "err": f"{type(e).__name__}: {e}"}
    candidates = [{"endpoint": r.endpoint.get("route_template"),
                   "principal": r.principal,
                   "verdict": (r.response_delta or {}).get("candidate")}
                  for r in result["findings"]]
    return {"status": "ok", "candidates": candidates,
            "rows": result["rows"], "briefs_n": len(result["briefs"]),
            "denied": sum(1 for row in result["rows"] if "status=0" in row)}

def run_lane(cls, endpoints, tokens, note, rows=None, emails=None, ariadne_goals=None, memoria_hint=""):
    """Run one lane as a MANAGER-IN-THE-LOOP (manager_loop.run_manager_lane). The manager is fed
    the map + Ariadne routes + Memoria recall and authors each action; these injected `fire`
    callables only execute the authored action and return a sanitized marker. Content-blind."""
    tok = tokens[0] if tokens else ""
    my_email = (emails or [""])[0]
    fire = {
        "probe":    lambda c: _fire_probe(_ensure_status_capture(c)),
        "listids":  lambda c: _fire_listids(c),
        "ownerdiff": lambda u: _verify_owner_diff(u, tok, my_email),
        # P1-2 graft: the deterministic BOLA slice supersedes ownerdiff when the manager
        # has a harvested {id} endpoint — slice_plan_for builds the plan, slice runs it.
        "slice":      lambda plan: _fire_slice(plan, tokens),
        "slice_plan": lambda route, ids=None: slice_plan_for(route, ids),
    }
    return ML.run_manager_lane(cls, endpoints, rows or [], tokens, emails or [],
                               ariadne_goals or [], memoria_hint, fire, note, step_cap=14)


# ============================================================================
def _autoturret_reflex(cls, success, work_id):
    """Reflex seam (north-star catch-net): when the manager's hand-authored lane does NOT
    confirm a class, fire ONE bounded autoturret card-sweep for that class -- the gunbelt
    CATALOG supplies recipes the manager didn't author. Fail-OPEN: down engine / no target /
    any error never breaks the run. Non-blocking: autoturret runs as its own proof-gated
    process and folds results back through its scrubbed recon/telemetry + review_queue surface,
    which the manager reads out-of-band (bb sitrep / MCP). Keeps the manager PRIMARY: only fires
    AFTER the manager's own attempt. Toggle GB_AUTOTURRET_REFLEX = off | on-fail (default) | always."""
    mode = os.environ.get("GB_AUTOTURRET_REFLEX", "on-fail").strip().lower()
    if mode in ("0", "off", "false", "no", ""):
        return
    if mode == "on-fail" and success:
        return  # manager already closed it; catalog is a catch-net, not reinforcement
    try:
        ttl = int(os.environ.get("GB_AUTOTURRET_REFLEX_TTL", "300"))
    except ValueError:
        ttl = 300
    dial = os.environ.get("GB_AUTOTURRET_REFLEX_DIAL", "full").strip() or "full"
    try:
        if os.environ.get("GB_AUTOTURRET_REFLEX_CATALOG", "1").strip().lower() not in ("0", "off", "false", "no", ""):
            os.environ["AUTOTURRET_CATALOG"] = "1"  # guarantee the reflex sweep actually fires gunbelt catalog cards
        res = MB.fire_autoturret(RUN_DIR, goal=cls, dial=dial, ttl=ttl,
                                 assessment_id=os.environ.get("BS2_ASSESSMENT_ID", "reflex"))
        log("autoturret_reflex", cls=cls, trigger=("fail" if not success else "always"),
            launched=bool(res.get("launched")), already=bool(res.get("already_firing")),
            ok=bool(res.get("ok")), note=str(res.get("error") or res.get("note") or "")[:100],
            ttl=ttl, dial=dial)
    except Exception as e:
        log("autoturret_reflex_err", cls=cls, err=f"{type(e).__name__}: {e}")


def main():
    global LENZ
    os.makedirs(RUN_DIR, exist_ok=True)
    # The harness working directory is legacy/non-canonical.  Publish a separate structural
    # mirror containing only counts, booleans and closed enums distilled by the hands model.
    LENZ = SafeLenzStream.mirror(steps=ITER_CAP)
    for f in ("worklist.json", "ariadne_facts.jsonl"):
        shutil.copy(f"{SRC}/{f}", f"{RUN_DIR}/{f}")
    json.dump({"target": TARGET, "proven": [], "apps": {"crapi": TARGET}, "negatives": []},
              open(f"{RUN_DIR}/recon.json", "w"))
    wl = f"{RUN_DIR}/worklist.json"

    log("boot", target=TARGET, posture=POSTURE, model=os.environ["TROOPER_MODEL"], iter_cap=ITER_CAP)

    # benign harness setup: provision two authed test accounts (not exploitation)
    _pairs = provision_tokens()
    tokens = [p[0] for p in _pairs]           # bearer strings (used by lane_objective)
    emails = [p[1] for p in _pairs]           # matching identities (used for owner-diff verify)
    log("provisioned", accounts=len(tokens), note="test-account bearer tokens for the trooper (setup)")
    if not tokens:
        log("abort", reason="provisioning yielded 0 tokens; troopers would flail tokenless")
        flush_log(); return

    # governed episode: one approval, one episode
    op = gseam("open", "--target", TARGET, "--run-dir", RUN_DIR)
    log("governed_open", cap=str(op.get("opened") or op)[:40])

    # fix #2: the SIGIL housekeeping choke-point
    hk = None
    try:
        hk = build_housekeeping()
        log("housekeeping_ready", routes="8-node-gunbelt-topology")
    except Exception as e:
        log("housekeeping_FAILED", err=f"{type(e).__name__}: {e}")

    solved, dispatched = set(), 0
    prev_goals_sig = None
    for it in range(1, ITER_CAP + 1):
        # ---- fix #1: recompute advisory over CURRENT state -----------------
        adv = MB.build_advisory(RUN_DIR, posture=POSTURE)
        goals = adv.get("goals", [])
        if os.environ.get("GB_ARIADNE", "on").strip().lower() in ("0", "off", "false", "no"):
            goals = []  # ablation: Ariadne routing disabled (fail-open, empty ladder)
        gsig = tuple((g.get("goal"), g.get("status"), g.get("unblocks_n")) for g in goals)
        replan = "SHIFTED" if (prev_goals_sig is not None and gsig != prev_goals_sig) else "stable"
        prev_goals_sig = gsig
        troops = [t for t in adv.get("troopers", []) if t.get("id") not in solved
                  and t.get("gate") in ("allowed", "approval")]
        log("advisory", iter=it, facts_n=adv.get("stamp", {}).get("facts_n"),
            goals_n=len(goals), grounded=sum(1 for g in goals if g.get("status") == "grounded"),
            recon_next=len(adv.get("recon_next", [])), troopers_open=len(troops),
            join=adv.get("join_src"), replan=replan)
        if not troops:
            log("loop_done", reason="no open troopers", iter=it); break

        top = troops[0]
        cls = top.get("bespoke", {}).get("class") or top.get("why", "").split()[0] if isinstance(top.get("bespoke"), dict) else None
        # resolve the worklist class this trooper covers
        rows = json.load(open(wl))
        cls = None
        for c in ("sqli", "nosqli", "broken-access-control"):
            if any(r.get("class") == c for r in rows) and c not in solved:
                # match trooper id to class via CLASS_JOIN reverse
                if top["id"] in getattr(TP, "CLASS_JOIN", {}).get(c, []) or c in top.get("why", ""):
                    cls = c; break
        if cls is None:
            # fall back to the highest-count remaining class
            from collections import Counter
            cc = Counter(r["class"] for r in rows if r["class"] not in solved)
            cls = cc.most_common(1)[0][0] if cc else None
        if cls is None:
            log("loop_done", reason="no unsolved class", iter=it); break
        cls_rows = [r for r in rows if r.get("class") == cls]
        endpoints = [r["endpoint"] for r in cls_rows]
        action = CLASS_ACTION.get(cls, "exploit.web")   # posture taxonomy -> ROE gate
        work_id = f"wo-{cls}-{it}"
        enter_id = f"enter-{cls}-{it}"

        # ---- fix #2: route dispatch through the housekeeping choke-point ----
        focus_ok = True
        if hk is not None:
            try:
                hk.enter_focus(focus_id=f"lane-{cls}-{it}",
                    question=f"Confirm {cls} on {len(endpoints)} crAPI endpoints?",
                    why_now=f"Top-ranked reachable lane (trooper {top['id']}, score {top.get('score')}).",
                    routes=("ariadne", "troopers"),
                    exit_condition="A class-confirmation signal or a proof-gated negative.",
                    return_to=None, max_turns=12, max_tokens=20000,
                    source="manager/run_deep_deepseek", event_id=enter_id)
                hk.record_decision(summary=f"dispatch {top['id']} against {cls} ({action})",
                    source="manager", evidence_event_ids=[enter_id])
            except Exception as e:
                focus_ok = False
                log("housekeeping_REJECT", iter=it, cls=cls, err=f"{type(e).__name__}: {e}")
        if not focus_ok:
            solved.add(cls); mark_solved(wl, cls); continue

        # ---- governed dispatch marker: hash-chained tool.completed for work_id ----
        gseam("exec", "--run-dir", RUN_DIR, "--class", "web.exploit", "--risk", "high",
              "--work-id", work_id, "--marker", f"dispatch:{cls}", "echo", f"dispatch {top['id']}")

        # ---- fix #3: measured-posture receipt for an exploit.* lane ---------
        if _measured_needs_receipt(action):
            roe_id = f"wo-roe-{cls}-{it}"
            gseam("exec", "--run-dir", RUN_DIR, "--class", "web.exploit", "--risk", "high",
                  "--work-id", roe_id, "--marker", f"roe:{action}", "echo", f"roe-approve {action}")
            gseam("finding", "--run-dir", RUN_DIR, "--label", f"ROE-receipt:{action}",
                  "--class", cls, "--severity", "info", "--work-id", roe_id)
            log("posture_receipt", iter=it, action=action, posture=POSTURE, work_id=roe_id,
                note="measured gates exploit.* -> governed receipt minted (afk auto-approve)")

        # ---- dispatch as a MANAGER-IN-THE-LOOP lane (north star) -----------
        # Assemble the picture the manager reasons over: the Ariadne goal ladder (adv["goals"])
        # and Memoria's corpus recall for this class. The manager (Opus, in manager_loop) authors
        # every action from that picture; the trooper only fires it. No frozen `if <vuln>:` here.
        mem_hint = ""
        _memoria_on = os.environ.get("GB_MEMORIA", "on").strip().lower() not in ("0", "off", "false", "no")
        if MEM is not None and _memoria_on:
            try:
                mem_hint = MEM.hints_for(cls, cls_rows, TARGET, k=3, timeout=7) or ""
            except Exception:
                mem_hint = ""
        log("dispatch", iter=it, trooper=top["id"], cls=cls, action=action,
            endpoints=len(endpoints), model="opus-manager+" + os.environ["TROOPER_MODEL"],
            routes=len(goals), memoria=bool(mem_hint), mode="manager-in-loop")
        def _note(msg, _eid=enter_id):
            if hk is not None:
                try: hk.record_observation(summary=f"microstep {msg}", source="trooper",
                                           evidence_event_ids=[_eid])
                except Exception: pass
            manager_verb = ("DONE" if "manager DONE" in msg else
                            "FINDING" if "manager FINDING" in msg else
                            "INVALID" if "no valid action" in msg else "RUN")
            log("microstep", cls=cls, step=it, manager_verb=manager_verb,
                routes_n=len(goals), memoria=bool(mem_hint), detail=msg[:120])
        t0 = time.time()
        try:
            result = run_lane(cls, endpoints, tokens, _note, rows=cls_rows, emails=emails,
                              ariadne_goals=goals, memoria_hint=mem_hint)
        except Exception as e:
            import traceback
            log("lane_error", iter=it, cls=cls, err=f"{type(e).__name__}: {e}",
                where=traceback.format_exc().strip().splitlines()[-2][:160])
            result = {"success": False, "facts": [],
                      "telemetry": {"blocked": f"{type(e).__name__}: {e}"}, "cmds": []}
        dt = int(time.time() - t0)
        dispatched += 1

        # consume SCRUBBED facts/telemetry ONLY (never result['output'])
        tel = result.get("telemetry") or {}
        fact_keys = sorted({str(f).split("=", 1)[0] for f in (result.get("facts") or [])})
        log("trooper_result", iter=it, cls=cls, success=bool(result.get("success")),
            cmds=len(result.get("transcript") or result.get("cmds") or []), secs=dt,
            fact_keys=",".join(fact_keys) or "none",
            blocked=str(tel.get("blocked") or "")[:80])

        # ---- reflex: catalog-backed autoturret sweep when the manager's lane missed ----
        _autoturret_reflex(cls, bool(result.get("success")), work_id)

        # governed finding + independent verify when the class confirmed
        if result.get("success"):
            gseam("finding", "--run-dir", RUN_DIR, "--label", f"{cls}-confirmed",
                  "--class", cls, "--severity", "high", "--work-id", work_id)
            vr = gseam("verify", "--run-dir", RUN_DIR, "--work-id", work_id)
            ok = ("VERIFIED" in str(vr.get("err", "")) or "VERIFIED" in str(vr)) and "FAILED" not in str(vr)
            log("finding_verified", iter=it, cls=cls, work_id=work_id, verified=ok)

        added = ground(cls, endpoints, result)
        remaining = mark_solved(wl, cls)
        solved.add(cls)
        log("grounded", iter=it, cls=cls, facts_added=added, worklist_remaining=remaining)

        # ---- fix #2: checkpoint + close the focus frame --------------------
        if hk is not None:
            try:
                hk.checkpoint(summary=f"{cls}: {'confirmed' if result.get('success') else 'no-signal'}",
                    source="manager", open_loops=[], next_action="re-rank advisory",
                    evidence_event_ids=[enter_id])
                hk.close_focus(outcome="solved" if result.get("success") else "exhausted",
                    summary=f"lane {cls} closed", source="manager", evidence_event_ids=[enter_id])
            except Exception as e:
                log("housekeeping_close_err", iter=it, err=f"{type(e).__name__}")

    # ---- final telemetry -------------------------------------------------
    st = gseam("status", "--run-dir", RUN_DIR)
    log("final", dispatched=dispatched, solved=len(solved),
        events=st.get("events") or st.get("n_events"), chain=str(st.get("chain") or st.get("intact"))[:12])
    flush_log()
    print("\n=== SCRUBBED SUMMARY ===")
    print(json.dumps({"dispatched": dispatched, "solved_classes": sorted(solved),
                      "governed": st, "run_dir": RUN_DIR}, indent=1)[:1200])

if __name__ == "__main__":
    main()
