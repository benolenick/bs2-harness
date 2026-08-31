#!/usr/bin/env python3
"""
manager_bridge.py — the Opus MANAGER's tool surface for the autoturret engine.

Why this exists
---------------
autoturret (gunbelt/live/autoturret.py) is an autonomous, proof-gated engine. The
"manager" (an Opus/Claude session, content-blind) is supposed to DIRECT it — set the
goal, hold sweeps, inject strategy — and READ its grounded state. Until now that link
was three loose flat files the manager had to hand-poke (`hold`, `planner_goal`,
`manager_directives.md`) plus hand-run `cat recon.json` / `monitor.sh` to see anything.

This module turns that hand-cranked seam into a small, typed, CONTENT-BLIND surface:

    Levers  (write)  : set_goal() / set_hold() / add_directive() / set_directives()
    Status  (read)   : build_status() -> StatusPacket   (scrubbed, manager-safe)
    Handoff (read)   : read_review_queue()               (unverifiable-claim worklist)

The same contract the engine enforces is honoured here: the manager sees fact KEYS +
counts + safe values only. Any fact whose key is in SENSITIVE_KEYS (flag/cred/hash/...)
is surfaced as "<key> (captured)" — never its value. Raw output (`raw/*.txt`) and the
operator feed (`autoturret.ops.jsonl`) are NEVER read here.

It is dependency-free stdlib so it runs anywhere (CLI, MCP server, another agent).

Source-of-truth cross-refs (keep in sync):
    SENSITIVE_KEYS      -> autoturret.py:34
    lever file names    -> run_double_barrel.sh (hold / planner_goal / manager_directives.md)
    recon.json schema   -> autoturret.py:write_recon (:358)
"""
from __future__ import annotations
import os, sys, json, glob, time, subprocess, hashlib
from dataclasses import dataclass, field, asdict
from typing import Any

GUNBELT = os.environ.get("GB_HOME", "/opt/bs2")

# BS2 2.0 governed server (:8124). When reachable and steering the same atrun it governs,
# levers route through it so each steer is recorded (ledger event + hash-chained
# levers.audit.jsonl) AND still writes the flat file the engine reads. Direct-file write is
# the fallback when BS2 is down. Import is best-effort so this module works without it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import bs2_client
except Exception:
    bs2_client = None

# Advisory producers (contract: 2026-08-24-gunbelt-17-ARIADNE-advisory-contract-LOCKED).
# recon_advisor (Ariadne-facing, om-00) emits {stamp, goals, recon_next}; troopers
# (BS2-facing, this session) supplies the goal->trooper join + posture gate. Both
# best-effort so a missing half never breaks status.
sys.path.insert(0, os.path.join(GUNBELT, "live"))
try:
    import recon_advisor as _recon_advisor
except Exception:
    _recon_advisor = None
try:
    import importlib.util as _ilu
    _TROOPERS_PATH = "/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/troopers.py"
    _spec = _ilu.spec_from_file_location("bs2_troopers", _TROOPERS_PATH)
    _troopers = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _troopers          # required before exec: dataclass(slots=True)
    _spec.loader.exec_module(_troopers)          #   resolves its class via sys.modules
except Exception:
    _troopers = None


def _route_via_bs2(run_dir: str) -> bool:
    """Route a lever through the governed server only when (a) it's importable, (b) BS2 is
    reachable, (c) the caller hasn't forced direct writes, and (d) the run dir we're steering
    IS the atrun BS2's apply_lever writes to — otherwise BS2 would write a different dir than
    the engine reads."""
    if bs2_client is None or os.environ.get("MANAGER_LEVERS_DIRECT") == "1":
        return False
    try:
        if os.path.realpath(run_dir) != os.path.realpath(bs2_client.BS2_TELEMETRY_DIR):
            return False
        return bs2_client.reachable()
    except Exception:
        return False

# Mirror of autoturret.py:34 — a fact whose key is here is a SECRET: surface the key, never
# the value. (Kept as a literal copy so this module has zero import coupling to the engine;
# a drift check lives in the self-test at the bottom.)
SENSITIVE_KEYS = {"flag", "cred", "dc_cred", "hash", "ntlm", "secret", "secret_key_base",
                  "token", "password", "pass", "key", "priv", "ssh_key"}

# Lever filenames, written into the ATRUN dir (the dir that also holds recon.json).
LEVER_HOLD = "hold"
LEVER_GOAL = "planner_goal"
LEVER_DIRECTIVES = "manager_directives.md"

# Manager-safe artifacts we may read. (autoturret.ops.jsonl and raw/ are deliberately absent.)
A_RECON = "recon.json"
A_LANES = "lanes.json"
A_FEED = "autoturret.jsonl"          # already scrubbed by the engine
A_TELEM = "telemetry_feed.json"      # may not exist (only when troopers return telemetry)
A_REVIEW = "review_queue.json"

# Engine source (the live autoturret tree) — imported lazily by the EXECUTE primitives below.
LIVE_DIR = os.environ.get("GB_LIVE_DIR", os.path.join(GUNBELT, "live"))
DOMAIN = os.environ.get("GB_DOMAIN", "inlanefreight.local")
A_MGR_ACTIONS = "manager_actions.jsonl"      # audit log of manager-issued dispatch/fire (scrubbed)


# ----------------------------------------------------------------------------- typed objects
@dataclass
class Directive:
    """A manager -> engine steering instruction. This is the schema the design called for
    ('Directive'): a bounded, abstract intent the autonomous engine obeys on its own terms."""
    goal: str | None = None                 # planner goal term, e.g. 'rce_as:drupal', 'root'
    hold: bool | None = None                # pause/resume sweeps
    directive_text: str | None = None       # abstract strategy injected into trooper objectives
    append: bool = False                    # append directive_text vs replace

    def to_dict(self) -> dict: return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class StatusPacket:
    """Distilled, content-blind snapshot of a run for the manager (the design's 'StatusPacket').
    Values are scrubbed: secret facts appear as counts of captured keys, never their content."""
    run_dir: str
    target: str = ""
    live: bool = False                      # engine process alive right now
    recon_age_s: int | None = None          # seconds since recon.json last written
    owned: bool = False
    stopped: str = ""                       # engine's stop reason, e.g. 'frontier dry'
    counts: dict = field(default_factory=dict)          # fired / hits / flags
    apps: dict = field(default_factory=dict)            # app -> vhost (safe)
    unlocked_keys: list = field(default_factory=list)   # capability keys unlocked (safe)
    grounded_safe: list = field(default_factory=list)   # non-secret facts, value shown
    captured_secrets: dict = field(default_factory=dict)  # secret key -> count (value withheld)
    levers: dict = field(default_factory=dict)          # current hold/goal/directives state
    review_queue: dict = field(default_factory=dict)    # {count, items:[{card,phase,reason,rc}]}
    recent_feed: list = field(default_factory=list)     # last scrubbed feed rows
    governed: dict = field(default_factory=dict)        # BS2 2.0 (:8124) health/battle + lever audit
    warnings: list = field(default_factory=list)        # anything odd (stale/missing files)

    def to_dict(self) -> dict: return asdict(self)


# ----------------------------------------------------------------------------- run resolution
def find_run(run_dir: str | None = None) -> str:
    """Resolve the active ATRUN dir (the one holding recon.json + the levers).
    Order: explicit arg > $AUTOTURRET_RUN > newest */recon.json under gunbelt > default."""
    if run_dir:
        return os.path.abspath(run_dir)
    env = os.environ.get("AUTOTURRET_RUN")
    if env and os.path.isdir(env):
        return os.path.abspath(env)
    # Known run locations: gunbelt's own run dirs AND the double-barrel launcher's ATRUN,
    # which lives outside gunbelt (run_double_barrel.sh: DIR=.../bs2-memoria, ATRUN=$DIR/atrun).
    extra = [p for p in (os.environ.get("GB_RUN_DIRS", "").split(":")) if p]
    db_atrun = ["/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria/atrun",
                "/mnt/acer/your-host-offload/Desktop/HTB/enterprise-ab/bs2-memoria/atrun"]
    cands = (glob.glob(f"{GUNBELT}/run*/recon.json")
             + glob.glob(f"{GUNBELT}/run*/atrun/recon.json")
             + glob.glob(f"{GUNBELT}/run/recon.json")
             + [os.path.join(d, "recon.json") for d in (db_atrun + extra)])
    cands = [p for p in cands if os.path.exists(p)]
    if cands:
        newest = max(cands, key=lambda p: os.path.getmtime(p))
        return os.path.dirname(os.path.abspath(newest))
    return os.path.join(GUNBELT, "run")


def _load(run_dir: str, name: str, default: Any = None) -> Any:
    p = os.path.join(run_dir, name)
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return default


def _engine_live(run_dir: str | None = None) -> bool:
    """Is an autoturret engine process alive FOR THIS RUN? The launcher invokes
    `autoturret.py --run-dir <ATRUN>`, so we match the run dir in argv to avoid reporting
    a different run's process as this one's. Falls back to a global match only if run_dir
    is unknown."""
    try:
        pat = f"autoturret.py.*{run_dir}" if run_dir else "autoturret.py"
        r = subprocess.run(["pgrep", "-f", pat], capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def _scrub_fact(fact: str) -> tuple[str, bool]:
    """Return (key, is_secret). Mirrors autoturret.py:306 semantics."""
    key = fact.split("=", 1)[0].strip()
    return key, (key in SENSITIVE_KEYS)


# ----------------------------------------------------------------------------- READ: status
def build_status(run_dir: str | None = None, feed_tail: int = 12) -> StatusPacket:
    run_dir = find_run(run_dir)
    sp = StatusPacket(run_dir=run_dir)

    recon = _load(run_dir, A_RECON)
    if recon is None:
        sp.warnings.append(f"no {A_RECON} in run dir (run not started or wrong dir)")
        sp.live = _engine_live(run_dir)
        sp.levers = _read_levers(run_dir)
        return sp

    rp = os.path.join(run_dir, A_RECON)
    sp.recon_age_s = int(time.time() - os.path.getmtime(rp))
    sp.target = recon.get("target", "")
    sp.owned = bool(recon.get("owned"))
    sp.stopped = recon.get("stopped", "")
    sp.counts = {"fired": recon.get("fired", 0), "hits": recon.get("hits", 0),
                 "flags": len(recon.get("flags") or [])}
    sp.apps = recon.get("apps", {}) or {}
    sp.unlocked_keys = recon.get("unlocked_keys", []) or []

    # proven_facts: split into safe (value shown) vs secret (key + count only). NEVER read
    # the `evidence` field — it holds raw captured output that can contain the secret.
    secret_counts: dict = {}
    safe: list = []
    seen_safe = set()
    for pf in (recon.get("proven_facts") or []):
        fact = pf.get("fact", "") if isinstance(pf, dict) else str(pf)
        if not fact:
            continue
        key, is_secret = _scrub_fact(fact)
        if is_secret:
            secret_counts[key] = secret_counts.get(key, 0) + 1
        else:
            if fact not in seen_safe:
                seen_safe.add(fact)
                safe.append(fact)
    sp.captured_secrets = secret_counts
    sp.grounded_safe = safe

    sp.levers = _read_levers(run_dir)
    sp.live = _engine_live(run_dir)
    if sp.recon_age_s is not None and sp.recon_age_s > 300 and not sp.live:
        sp.warnings.append(f"recon is stale ({sp.recon_age_s}s) and no engine process alive — run appears stopped")

    # review queue (handoff worklist) — safe fields only, drop the raw/ pointer.
    rq = _load(run_dir, A_REVIEW, {}) or {}
    items = []
    for it in (rq.get("items") or []):
        items.append({k: it.get(k) for k in ("card", "phase", "reason", "rc", "gate") if k in it})
    sp.review_queue = {"count": rq.get("count", len(items)), "items": items}

    # recent manager feed — already engine-scrubbed, safe to echo the tail.
    feed = _read_feed_tail(run_dir, feed_tail)
    sp.recent_feed = feed

    # governed view: BS2 2.0 (:8124) health/battle + this run's hash-chained lever audit.
    gov = {}
    if bs2_client is not None:
        try:
            gov = bs2_client.governed_summary()
        except Exception as e:
            gov = {"url": getattr(bs2_client, "BS2_URL", "?"), "reachable": False, "error": str(e)}
    gov["lever_audit"] = _lever_audit_tail(run_dir)
    gov["levers_governed_by"] = ("bs2:8124" if _route_via_bs2(run_dir) else "direct-file")
    sp.governed = gov
    return sp


def _lever_audit_tail(run_dir: str, n: int = 3) -> list:
    """Tail of the hash-chained lever audit BS2's apply_lever writes into the atrun. Safe:
    goal/hold previews are non-secret; directives are surfaced as a char-count preview only."""
    p = os.path.join(run_dir, "levers.audit.jsonl")
    out = []
    try:
        with open(p) as f:
            for ln in f.readlines()[-n:]:
                try:
                    r = json.loads(ln)
                    out.append({k: r.get(k) for k in ("action", "preview", "actor_id", "ts") if k in r})
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _read_levers(run_dir: str) -> dict:
    goal = ""
    try:
        with open(os.path.join(run_dir, LEVER_GOAL)) as f:
            goal = f.read().strip()
    except Exception:
        goal = ""
    d_path = os.path.join(run_dir, LEVER_DIRECTIVES)
    d_present = os.path.exists(d_path)
    d_first = ""
    if d_present:
        try:
            with open(d_path) as f:
                for line in f:
                    if line.strip():
                        d_first = line.strip()[:120]
                        break
        except Exception:
            pass
    return {"hold": os.path.exists(os.path.join(run_dir, LEVER_HOLD)),
            "goal": goal or "(default: rce)",
            "directives_present": d_present,
            "directives_first_line": d_first}


def _read_feed_tail(run_dir: str, n: int) -> list:
    p = os.path.join(run_dir, A_FEED)
    rows = []
    try:
        with open(p) as f:
            lines = f.readlines()[-n:]
        for ln in lines:
            try:
                r = json.loads(ln)
                rows.append({k: r.get(k) for k in ("kind", "tool", "text", "lane", "phase") if r.get(k)})
            except Exception:
                continue
    except Exception:
        pass
    return rows


def read_review_queue(run_dir: str | None = None) -> dict:
    return build_status(run_dir).review_queue


# ----------------------------------------------------------------------------- WRITE: levers
def _atrun(run_dir: str | None) -> str:
    run_dir = find_run(run_dir)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


A_LEVER_AUDIT = "levers.audit.jsonl"


def _lever_audit_append(run_dir: str, action: str, preview: str,
                        actor_id: str = "manager-bridge") -> dict:
    """Append ONE hash-chained audit row in the same shape BS2's apply_lever writes
    (action/preview/actor_id/ts + prev/hash). The chain links every row to its
    predecessor, so a torn or forged audit is detectable. Durably synced. Raises on
    any write failure — callers fence, never proceed unaudited."""
    p = os.path.join(run_dir, A_LEVER_AUDIT)
    prev = ""
    try:
        with open(p) as f:
            for ln in f:
                try:
                    prev = json.loads(ln).get("hash") or prev
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    row = {"action": action, "preview": preview, "actor_id": actor_id,
           "ts": int(time.time()), "prev": prev}
    row["hash"] = hashlib.sha256(
        json.dumps(row, sort_keys=True).encode()).hexdigest()[:32]
    with open(p, "a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return row


def _direct_lever(run_dir: str, action: str, preview: str, materialize) -> dict:
    """P1-4 order for the direct-file fallback: INTENT event (durably synced) ->
    materialize the control file -> COMPLETION event bound to the intent and the new
    state digest. Any failure returns a TYPED indeterminate result; the flat file is
    never a silent authority."""
    try:
        intent = _lever_audit_append(run_dir, f"{action}:intent", preview)
    except OSError as e:
        return {"ok": False,
                "error": f"indeterminate: audit intent failed ({e}) — lever not applied"}
    try:
        digest = materialize()
    except OSError as e:
        return {"ok": False,
                "error": (f"indeterminate: materialize failed ({e}) — intent "
                          f"{intent['hash'][:8]} recorded but state unchanged")}
    try:
        _lever_audit_append(run_dir, f"{action}:complete", f"state {digest}")
    except OSError as e:
        return {"ok": False, "applied": True, "digest": digest,
                "error": (f"indeterminate: state applied but completion audit failed "
                          f"({e}) — reconcile {A_LEVER_AUDIT}")}
    return {"ok": True, "digest": digest, "intent": intent["hash"][:8]}


def set_goal(goal: str, run_dir: str | None = None) -> dict:
    """LEVER 2 — write the resettable planner goal (e.g. 'rce_as:drupal', 'root', 'read_file:/etc/passwd').
    The bash loop reads this on the next iteration and passes it to Ariadne. Routes through the
    BS2 governed server when it's steering the same atrun, else writes the file directly."""
    rd = _atrun(run_dir)
    goal = (goal or "").strip()
    if not goal:
        return {"ok": False, "error": "empty goal"}
    if _route_via_bs2(rd):
        try:
            r = bs2_client.lever("set_goal", goal)
            return {"ok": True, "lever": "planner_goal", "goal": goal, "run_dir": rd,
                    "via": "bs2:8124", "governed": True, "audit_head": r.get("hash")}
        except Exception as e:
            _direct_note = f"bs2 route failed ({e}); wrote file directly"
    else:
        _direct_note = None
    def _mat():
        with open(os.path.join(rd, LEVER_GOAL), "w") as f:
            f.write(goal + "\n")
        return hashlib.sha256(goal.encode()).hexdigest()[:16]
    res = _direct_lever(rd, "set_goal", f"goal:{goal[:60]}", _mat)
    if not res["ok"]:
        return res
    out = {"ok": True, "lever": "planner_goal", "goal": goal, "run_dir": rd,
           "via": "direct-file", "audit_head": res["digest"]}
    if _direct_note:
        out["note"] = _direct_note
    return out


def set_hold(on: bool, run_dir: str | None = None) -> dict:
    """LEVER 1 — pause (on=True) or resume (on=False) sweeps between iterations."""
    rd = _atrun(run_dir)
    if _route_via_bs2(rd):
        try:
            r = bs2_client.lever("set_hold", bool(on))
            return {"ok": True, "lever": "hold", "held": bool(on), "run_dir": rd,
                    "via": "bs2:8124", "governed": True, "audit_head": r.get("hash")}
        except Exception as e:
            _direct_note = f"bs2 route failed ({e}); wrote file directly"
    else:
        _direct_note = None
    hp = os.path.join(rd, LEVER_HOLD)

    def _mat():
        if on:
            open(hp, "w").close()
        else:
            try:
                os.remove(hp)
            except FileNotFoundError:
                pass
        return hashlib.sha256(f"hold:{int(bool(on))}".encode()).hexdigest()[:16]
    res = _direct_lever(rd, "set_hold", f"hold:{int(bool(on))}", _mat)
    if not res["ok"]:
        return res
    out = {"ok": True, "lever": "hold", "held": on, "run_dir": rd,
           "via": "direct-file", "audit_head": res["digest"]}
    if _direct_note:
        out["note"] = _direct_note
    return out


def set_directives(text: str, run_dir: str | None = None, append: bool = False) -> dict:
    """LEVER 3 — abstract, content-blind strategy injected into EVERY trooper objective.
    Keep it strategy, not commands ('prioritise dev.* for source/cred leaks'), never a secret.
    Routes through BS2 when governing the same atrun. BS2 set_directives REPLACES, so to honour
    append we send the concatenation of the existing file + new text."""
    rd = _atrun(run_dir)
    text = (text or "").rstrip() + "\n"
    if _route_via_bs2(rd):
        try:
            payload = text
            if append:
                try:
                    with open(os.path.join(rd, LEVER_DIRECTIVES)) as f:
                        payload = f.read() + text
                except FileNotFoundError:
                    payload = text
            r = bs2_client.lever("set_directives", payload)
            return {"ok": True, "lever": "manager_directives.md", "append": append,
                    "bytes": len(payload), "run_dir": rd, "via": "bs2:8124",
                    "governed": True, "audit_head": r.get("hash")}
        except Exception as e:
            _direct_note = f"bs2 route failed ({e}); wrote file directly"
    else:
        _direct_note = None
    d_path = os.path.join(rd, LEVER_DIRECTIVES)
    mode = "a" if append else "w"

    def _mat():
        with open(d_path, mode) as f:
            f.write(text)
        with open(d_path) as f:
            return hashlib.sha256(f.read().encode()).hexdigest()[:16]
    res = _direct_lever(rd, "set_directives", f"directives:{len(text)}B", _mat)
    if not res["ok"]:
        return res
    out = {"ok": True, "lever": "manager_directives.md", "append": append,
           "bytes": len(text), "run_dir": rd, "via": "direct-file",
           "audit_head": res["digest"]}
    if _direct_note:
        out["note"] = _direct_note
    return out


def add_directive(text: str, run_dir: str | None = None) -> dict:
    return set_directives(text, run_dir=run_dir, append=True)


def apply_directive(d: Directive, run_dir: str | None = None) -> dict:
    """Apply a whole Directive object (any subset of levers) atomically-ish, in order."""
    out = {}
    if d.hold is not None:
        out["hold"] = set_hold(d.hold, run_dir)
    if d.goal is not None:
        out["goal"] = set_goal(d.goal, run_dir)
    if d.directive_text is not None:
        out["directive"] = set_directives(d.directive_text, run_dir, append=d.append)
    return {"ok": True, "applied": out}


# ----------------------------------------------------------------------------- CLI
# ============================================================================ EXECUTE
# The manager doesn't only STEER the autopilot — it DRIVES. These two primitives are the
# trigger the cockpit was missing: dispatch a trooper with a concrete task NOW, and fire the
# autoturret engine NOW. Both are content-blind: the trooper's raw output / evidence and the
# engine's operator-tier stdout NEVER return to the manager — only scrubbed telemetry, safe
# fact KEYS, and counts do.

import re as _re
_SCRUB = [
    (_re.compile(r'(?:HTB|FLAG)\{[^}]*\}', _re.I), '<flag>'),
    (_re.compile(r'\$(?:P|H|apr1|1|2[aby]|5|6)\$[^\s"\']+'), '<hash>'),
    (_re.compile(r'\b[0-9a-fA-F]{32,}\b'), '<hex>'),
    (_re.compile(r'((?:pass(?:word)?|pwd|token|secret|key|ntlm|hash|priv)\s*[=:]\s*)(\S+)', _re.I), r'\1<redacted>'),
]
def _scrub_text(text: str) -> str:
    """Mirror of autoturret._scrub_telemetry — deterministic secret redaction over any string
    that will reach the manager. Kept as a literal copy (zero import coupling); drift-checked
    in the self-test."""
    t = str(text or "")
    for pat, repl in _SCRUB:
        t = pat.sub(repl, t)
    return t.strip()[:400]


def _safe_facts(facts) -> dict:
    """Split a trooper's returned facts into safe (value shown) vs secret (key -> count)."""
    safe, secret = [], {}
    for f in (facts or []):
        fact = f if isinstance(f, str) else (f.get("fact") if isinstance(f, dict) else str(f))
        if not fact:
            continue
        key, is_secret = _scrub_fact(fact)
        if is_secret:
            secret[key] = secret.get(key, 0) + 1
        else:
            safe.append(_scrub_text(fact))
    return {"safe": safe, "secret_counts": secret}


def _log_action(run_dir: str, entry: dict) -> None:
    """Append a scrubbed audit line of a manager-issued action so the cockpit can show what the
    manager did (never any secret — entry must be pre-scrubbed)."""
    try:
        with open(os.path.join(run_dir, A_MGR_ACTIONS), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _target_of(run_dir: str) -> str:
    recon = _load(run_dir, A_RECON) or {}
    return recon.get("target", "")


def _fill_objective(run_dir: str, objective: str) -> str:
    """Light parity with the engine's _fill: substitute known app vhosts and append the standing
    manager directives, so a manually dispatched trooper gets the same context an auto one does."""
    recon = _load(run_dir, A_RECON) or {}
    apps = recon.get("apps", {}) or {}
    def host(app):
        v = apps.get(app, "")
        return v if (v and not str(v).isdigit()) else f"{app}.{DOMAIN}"
    o = (objective.replace("{gitlab_host}", host("gitlab"))
                  .replace("{wp_host}", host("wordpress"))
                  .replace("{drupal_host}", host("drupal")))
    try:
        dp = os.path.join(run_dir, LEVER_DIRECTIVES)
        if os.path.exists(dp):
            txt = open(dp, errors="ignore").read().strip()
            if txt:
                o += ("\n\nMANAGER DIRECTIVES (standing orders — abstract strategy; YOU pick the "
                      "exact commands/flags):\n" + txt)
    except Exception:
        pass
    # The same restrictive runtime policy shown in BS2 is injected into the hands'
    # context. This is guidance only; target_exec.py independently enforces it.
    policy_path = os.environ.get("BS2_GOVERNANCE_POLICY", "").strip()
    if policy_path:
        try:
            policy = json.load(open(policy_path, encoding="utf-8"))
            soft = [item for item in policy.get("soft_directives", []) if isinstance(item, str)]
            o += (
                "\n\nRUNTIME GOVERNANCE (hard rules are machine-enforced; this prose does not grant authority):"
                "\n- Never issue a delete command."
                f"\n- Network mode: {policy.get('network_mode', 'deny')}."
                f"\n- Per-host budget: {policy.get('max_actions_per_host', '?')} actions per "
                f"{policy.get('budget_window_seconds', '?')} seconds."
                "\n- Stop if the target or impact is ambiguous."
            )
            if soft:
                o += "\nSOFT OPERATOR DIRECTIVES (advisory):\n" + "\n".join(f"- {item}" for item in soft)
        except Exception:
            o += "\n\nRUNTIME GOVERNANCE: policy unreadable; assume network and deletion are denied."
    return o


def dispatch_trooper(objective: str, run_dir: str | None = None, target: str | None = None,
                     model: str | None = None, assessment_id: str = "unbound",
                     run_id: str = "unbound") -> dict:
    """MANAGER -> TROOPER, concrete task NOW. The manager writes what to do (which tool/technique,
    against what); one trooper executes it on-target and returns manager-safe telemetry. This is
    the 'manager tells the trooper what to do' primitive — the manager directs, the trooper (not
    the manager) issues the on-target commands (manager-only guardrail preserved).

    Returns: success bool, scrubbed telemetry {observed,tried,blocked,next}, safe fact strings,
    secret fact key->count. NEVER the trooper's raw output or evidence value."""
    rd = _atrun(run_dir)
    objective = (objective or "").strip()
    if not objective:
        return {"ok": False, "error": "empty objective"}
    tgt = target or _target_of(rd)
    if not tgt:
        return {"ok": False, "error": "no target (pass target= or start a run first)"}
    try:
        if LIVE_DIR not in sys.path:
            sys.path.insert(0, LIVE_DIR)
        import trooper as _T
    except Exception as e:
        return {"ok": False, "error": f"cannot import engine trooper from {LIVE_DIR}: {e}"}
    if model:
        try: _T.MODEL = model
        except Exception: pass
    obj = _fill_objective(rd, objective)
    lane = {"id": f"mgr-dispatch-{int(time.time())}", "target": tgt, "objective": obj}
    try:
        with _T._texec.governance_context(
            assessment_id=assessment_id, run_id=run_id or lane["id"]
        ):
            v = _T.Trooper().fire(lane) or {}
    except Exception as e:
        return {"ok": False, "error": f"trooper fire failed: {e}", "target": tgt}
    tel = v.get("telemetry") or {}
    safe_tel = {k: _scrub_text(tel.get(k, "")) for k in ("observed", "tried", "blocked", "next")}
    facts = _safe_facts(v.get("facts"))
    out = {
        "ok": True, "lane": lane["id"], "target": tgt, "model": getattr(_T, "MODEL", "?"),
        "success": bool(v.get("success")),
        "telemetry": {k: val for k, val in safe_tel.items() if val},
        "facts_safe": facts["safe"],
        "captured_secret_keys": facts["secret_counts"],   # value withheld
    }
    _log_action(rd, {"ts": int(time.time()), "action": "dispatch", "lane": lane["id"],
                     "target": tgt, "objective": _scrub_text(objective)[:200],
                     "success": out["success"], "telemetry": out["telemetry"],
                     "secret_keys": list(facts["secret_counts"])})
    return out


def fire_autoturret(run_dir: str | None = None, goal: str | None = None, dial: str = "full",
                    ttl: int = 900, assessment_id: str = "unbound") -> dict:
    """MANAGER FIRES THE ENGINE. Triggers one bounded autoturret card-sweep NOW against the run's
    target. If the engine is already firing on this run dir (the double-barrel loop), it does NOT
    launch a duplicate — it ensures hold is off and reports the in-flight run. Content-blind: the
    launched process's operator-tier stdout goes to a log file in the run dir (path returned, never
    contents); results reach the manager only through the scrubbed recon/telemetry surface."""
    rd = _atrun(run_dir)
    tgt = _target_of(rd)
    if not tgt:
        return {"ok": False, "error": "no target in recon.json (start a run first)"}
    if _engine_live(rd):
        # don't stack a second engine on the same dir; make sure it isn't paused, then report.
        try: set_hold(False, rd)
        except Exception: pass
        _log_action(rd, {"ts": int(time.time()), "action": "fire", "result": "already_firing",
                         "target": tgt})
        return {"ok": True, "launched": False, "already_firing": True, "target": tgt,
                "note": "engine already sweeping this run dir; ensured hold=off (autopilot engaged)"}
    at = os.path.join(LIVE_DIR, "autoturret.py")
    if not os.path.exists(at):
        return {"ok": False, "error": f"autoturret.py not found at {at}"}
    try: set_hold(False, rd)
    except Exception: pass
    cmd = [sys.executable, at, "--target", tgt, "--dial", dial, "--run-dir", rd, "--ttl", str(int(ttl))]
    g = (goal or "").strip()
    if g:
        cmd += ["--planner", g]
    log_path = os.path.join(rd, f"autoturret.manfire.{int(time.time())}.log")
    try:
        logf = open(log_path, "ab")
        child_env = dict(os.environ)
        child_env["BS2_ASSESSMENT_ID"] = assessment_id or "unbound"
        child_env["BS2_RUN_ID"] = os.path.basename(rd.rstrip(os.sep)) or "unbound"
        proc = subprocess.Popen(cmd, cwd=LIVE_DIR, stdout=logf, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True,
                                env=child_env)
    except Exception as e:
        return {"ok": False, "error": f"failed to launch autoturret: {e}"}
    _log_action(rd, {"ts": int(time.time()), "action": "fire", "result": "launched",
                     "target": tgt, "dial": dial, "goal": g or "(default)", "ttl": int(ttl),
                     "pid": proc.pid})
    return {"ok": True, "launched": True, "pid": proc.pid, "target": tgt, "dial": dial,
            "goal": g or "(default: rce)", "ttl": int(ttl), "log": log_path,
            "note": "operator-tier stdout in log (path only, never returned to manager)"}


def _print(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=2))
        return
    if isinstance(obj, StatusPacket):
        obj = obj.to_dict()
    if isinstance(obj, dict) and "counts" in obj:  # a status packet
        s = obj
        live = "LIVE" if s["live"] else "stopped"
        print(f"● run: {s['run_dir']}")
        print(f"  target {s['target']}  [{live}]  recon age {s['recon_age_s']}s")
        print(f"  owned={s['owned']}  stopped='{s['stopped']}'  "
              f"fired={s['counts'].get('fired')} hits={s['counts'].get('hits')} flags={s['counts'].get('flags')}")
        if s['captured_secrets']:
            print("  captured (value withheld): " + ", ".join(f"{k}×{v}" for k, v in s['captured_secrets'].items()))
        if s['apps']:
            print("  apps: " + ", ".join(f"{k}->{v}" for k, v in s['apps'].items()))
        if s['unlocked_keys']:
            print("  unlocked: " + ", ".join(s['unlocked_keys']))
        lv = s['levers']
        print(f"  levers: hold={lv.get('hold')}  goal='{lv.get('goal')}'  directives={lv.get('directives_present')}")
        rq = s['review_queue']
        print(f"  review_queue: {rq.get('count', 0)} item(s)")
        for it in rq.get("items", [])[:8]:
            print(f"    - {it.get('card')}  [{it.get('phase')}]  {it.get('reason')}")
        if s['warnings']:
            for w in s['warnings']:
                print(f"  ⚠ {w}")
        if s['grounded_safe']:
            print(f"  grounded ({len(s['grounded_safe'])}): " + ", ".join(s['grounded_safe'][:12])
                  + (" …" if len(s['grounded_safe']) > 12 else ""))
    else:
        print(json.dumps(obj, indent=2))


def _advisory_signals(recon: dict) -> list:
    """Derive recon/surface tokens for the trooper join from a recon.json.
    Content-blind: app names + fact KEYS only (never fact values / secrets)."""
    sig = []
    apps = recon.get("apps") or {}
    for k, v in apps.items():
        sig.append(str(k).lower())
        if isinstance(v, str) and v:
            sig.append(v.lower())          # version banner string
            sig += ["version", "banner"]   # a pinned app version => component-cve applies
    for f in (recon.get("proven_facts") or recon.get("proven") or []):
        key = f.get("fact") if isinstance(f, dict) else str(f)
        # keep only the predicate/app token before any '=' so no value leaks
        tok = str(key).split("=")[0].lower()
        sig.append(tok)
        if "vuln_present" in tok or "known_exploit" in tok:
            sig += ["version", "banner"]   # a named vuln/exploit => component-cve applies
    return sig


def _load_worklist(rd: str) -> list:
    """The web_surface_mapper's class-tagged worklist for this engagement, if any.
    Looks beside recon.json first, then any per-engagement surface dir. Class-blind
    to contents beyond the 'class' tag the mapper itself assigned."""
    # SCOPED TO THE ACTIVE RUN-DIR ONLY. Never glob across engagements: borrowing
    # another target's worklist attributes its surface to THIS target (a phantom-
    # target error). An empty/absent worklist here MUST degrade closed.
    import glob as _glob
    cands = [os.path.join(rd, "worklist.json")]
    cands += sorted(_glob.glob(os.path.join(rd, "**", "worklist.json"), recursive=True))
    for c in cands:
        try:
            rows = json.load(open(c))
            if isinstance(rows, list) and rows:
                return rows
        except Exception:
            continue
    return []


def build_advisory(run_dir: str | None = None,
                   posture: str = "broadside",
                   enabled=None) -> dict:
    """Assemble the single `advisory` field (the LOCKED contract).

    Merge point per the division of labor: recon_advisor (om-00) provides
    {stamp, goals, recon_next}; this session joins troopers[] + posture gates.
    Fail-safe: any missing producer degrades to an empty section, never raises.
    """
    rd = find_run(run_dir)
    recon_path = os.path.join(rd, "recon.json")
    adv = {"stamp": {"facts_n": 0, "corpus_hash": None, "ts": int(time.time())},
           "goals": [], "recon_next": [], "troopers": [], "posture": posture}
    recon = {}
    try:
        recon = json.load(open(recon_path))
    except Exception:
        pass
    # Ariadne half
    if _recon_advisor is not None:
        try:
            planner = _recon_advisor.advise_from_recon_json(recon_path)
            adv["stamp"] = planner.get("stamp", adv["stamp"])
            adv["goals"] = planner.get("goals", [])
            adv["recon_next"] = planner.get("recon_next", [])
        except Exception as e:
            adv["stamp"]["error"] = f"recon_advisor: {type(e).__name__}"
    # BS2 half: join troopers to the live goals, gated by posture.
    # Join source PRIORITY (best -> fallback):
    #   1. worklist.json  -> mapper's own endpoint CLASS tags (authoritative)
    #   2. recon.json     -> app-level fingerprint tokens (coarse fallback)
    if _troopers is not None:
        try:
            active = [g.get("goal") for g in adv["goals"]
                      if g.get("status") in ("grounded", "near", "needs_recon")] or None
            worklist = _load_worklist(rd)
            if worklist:
                adv["troopers"] = _troopers.advisory_from_worklist(
                    active, worklist, posture=posture, enabled=enabled)
                adv["join_src"] = "worklist"
            else:
                signals = _advisory_signals(recon)
                adv["troopers"] = _troopers.advisory_troopers(
                    active, signals, posture=posture, enabled=enabled)
                adv["join_src"] = "recon-tokens"
        except Exception as e:
            adv["troopers_error"] = f"troopers: {type(e).__name__}"
    return adv


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    run_dir = None
    if "--run-dir" in argv:
        i = argv.index("--run-dir")
        run_dir = argv[i + 1]
        del argv[i:i + 2]
    cmd = argv[0] if argv else "status"
    rest = argv[1:]

    if cmd == "status":
        _print(build_status(run_dir), as_json)
    elif cmd == "goal":
        _print(set_goal(" ".join(rest), run_dir), as_json)
    elif cmd == "hold":
        on = (rest[0].lower() in ("on", "true", "1", "yes")) if rest else True
        _print(set_hold(on, run_dir), as_json)
    elif cmd == "directive":
        _print(add_directive(" ".join(rest), run_dir), as_json)
    elif cmd == "set-directives":
        _print(set_directives(" ".join(rest), run_dir), as_json)
    elif cmd == "dispatch":
        # optional: --model NAME  --target IP  (rest = objective)
        model = None; tgt = None
        if "--model" in rest:
            i = rest.index("--model"); model = rest[i+1]; del rest[i:i+2]
        if "--target" in rest:
            i = rest.index("--target"); tgt = rest[i+1]; del rest[i:i+2]
        _print(dispatch_trooper(" ".join(rest), run_dir, target=tgt, model=model), True)
    elif cmd == "fire":
        # optional: --dial full|semi|manual  --ttl N   (rest[0] = goal, optional)
        dial = "full"; ttl = 900
        if "--dial" in rest:
            i = rest.index("--dial"); dial = rest[i+1]; del rest[i:i+2]
        if "--ttl" in rest:
            i = rest.index("--ttl"); ttl = int(rest[i+1]); del rest[i:i+2]
        goal = " ".join(rest) if rest else None
        _print(fire_autoturret(run_dir, goal=goal, dial=dial, ttl=ttl), True)
    elif cmd == "advise":
        # optional: --posture broadside|measured|surgical  --enabled csv
        posture = "broadside"; enabled = None
        if "--posture" in rest:
            i = rest.index("--posture"); posture = rest[i+1]; del rest[i:i+2]
        if "--enabled" in rest:
            i = rest.index("--enabled"); enabled = [x for x in rest[i+1].split(",") if x]; del rest[i:i+2]
        _print(build_advisory(run_dir, posture=posture, enabled=enabled), True)
    elif cmd == "review":
        _print(read_review_queue(run_dir), True)
    elif cmd == "which":
        print(find_run(run_dir))
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        print("usage: manager_bridge.py [status|goal <g>|hold on|off|directive <text>|"
              "set-directives <text>|dispatch <objective>|fire [goal]|advise [--posture P]|review|which] [--run-dir DIR] [--json]", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
