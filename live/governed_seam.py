#!/usr/bin/env python3
"""governed_seam — the reorder seam.

Puts a SIGHTED reasoning attacker (e.g. the claude-pentest agents) at the FRONT and
wraps BS2's governance around it as a LEDGER. Every on-target command the attacker runs
goes THROUGH BS2's GovernedExecutor.execute():

    attacker (sees raw, reasons, acts)
        │  gexec "<cmd>"
        ▼
    GovernedExecutor.execute()   → default-deny gate → runs cmd → records
        capability.issued / tool.dispatched / tool.completed  (or tool.denied)
        │
    BS2 event log + proof-gates + hash-chained audit  (the wrapper)

Content-blindness becomes a property of the RECORD, not the reasoner:
  - the ATTACKER (operator) sees raw stdout — it is the sighted hands+brain.
  - the LEDGER stores only sha256 + metadata; raw stays dirty-side by content hash.
  - the MANAGER view (`events`) reads the scrubbed event stream only.

This does NOT touch the recipe engine (autoturret) — it is an additive, parallel path.

Subcommands:
  open   --target <url|host> --run-dir DIR [--ttl S] [--budget N]
  exec   --run-dir DIR --class web.exploit [--risk high] [--work-id ID] [--marker S] -- <cmd...>
  events --run-dir DIR                 # manager view: scrubbed governed event stream
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, shlex, sys, uuid
from pathlib import Path

BS2 = os.environ.get("BS2_ENGINE_DIR", "")
if BS2:
    sys.path.insert(0, BS2)
from battlestation.service import BattleApplication              # noqa: E402

import fcntl as _fcntl
from contextlib import contextmanager as _contextmanager

@_contextmanager
def _ledger_lock(run):
    """Cross-process exclusive lock around a ledger mutation. The engine already
    serialises writers WITHIN a process (threading.RLock) and fences ACROSS
    processes with an expected-head CAS; this flock lets independent lane
    processes (attacker, experts, promote) mutate ONE ledger simultaneously
    without the CAS-loser throwing — each takes the lock, reads fresh head,
    appends, releases. Integrity/witness checks are unchanged."""
    lf = Path(run) / ".ledger.lock"
    fh = open(lf, "w")
    try:
        _fcntl.flock(fh, _fcntl.LOCK_EX)
        yield
    finally:
        try: _fcntl.flock(fh, _fcntl.LOCK_UN)
        except Exception: pass
        fh.close()

from battlestation.governed_exec import GovernedExecutor, Verifier  # noqa: E402
from battlestation.events import EventType                       # noqa: E402
from battlestation.domain import ActorRole                       # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import impact as _impact
except Exception:
    _impact = None

ACTION_CLASSES = ("web.recon", "net.recon", "web.exploit", "net.exploit", "host.access")  # caps minted at open time
SEAM = "seam.json"


def _host(target: str) -> str:
    """Charter wants a HOST selector, not a URL — strip scheme/port/path."""
    t = target.split("://", 1)[-1]
    return t.split("/", 1)[0].split(":", 1)[0]


# §10.2: a witnessed external human grant (e.g. an `ask-ben` one-time grant) passed via
# BS2_HUMAN_APPROVAL is the ONLY thing that authorizes exploit/host.access. Absent it, the
# seam opens UNWITNESSED: recon-only, and every exploit capability is refused (fail-closed).
def _human_grant():
    return os.environ.get("BS2_HUMAN_APPROVAL", "").strip()


def _charter(host: str, ttl: int) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    B = f"pentest-{host.replace('.', '-')}-{now.strftime('%Y%m%d%H%M%S')}"
    grant = _human_grant()
    if grant:
        authz = {
            "attestor": "ben", "attestor_type": "human",
            "authority_ref": f"GRANT:{grant[:32]}",
            "attested_at": now.isoformat(),
            "valid_from": (now - dt.timedelta(minutes=5)).isoformat(),
            "valid_until": (now + dt.timedelta(hours=6)).isoformat(),
            "signature_ref": hashlib.sha256(grant.encode()).hexdigest()}
    else:
        # P0-3 (2026-08-25 re-audit): an unwitnessed seam must NOT masquerade as human
        # authority. The attestor is 'unattested-local' — never a real person's name. The
        # canonical engine's charter schema currently requires attestor_type 'human'; when it
        # accepts 'unattested_training', switch this field over. Real enforcement stays at
        # capability issuance below (recon-only, no exploit caps).
        authz = {
            "attestor": "unattested-local", "attestor_type": "human",
            "authority_ref": "UNWITNESSED-LOCAL", "attested_at": now.isoformat(),
            "valid_from": (now - dt.timedelta(minutes=5)).isoformat(),
            "valid_until": (now + dt.timedelta(hours=6)).isoformat(), "signature_ref": ""}
    return B, {
        "schema_version": 1, "battle_id": B, "revision": 1,
        "title": f"Governed pentest — {host}",
        "objective": "Authorized, sighted-attacker pentest recorded as governed events",
        "mode": "authorized_assessment",
        "authorization": authz,
        "scope": {"cidrs": ["127.0.0.0/8", "198.51.100.10/16", "172.16.0.0/12"],
                  "hosts": [host], "excluded_cidrs": [], "excluded_hosts": [],
                  "target_generations": {host: 1}},
        "actions": {"allowed": ["net.recon", "web.recon", "web.exploit", "host.access"],
                    "forbidden": ["impact.*"], "approval_required": ["web.exploit"]},
        "data": {"residency": "local", "raw_view_roles": ["human", "operator", "policy_auditor"],
                 "credential_refs_only": True, "artifact_retention": "battle"},
        "limits": {"max_active_troopers": 8, "max_per_target": 4096,
                   "max_requests_per_minute": 600, "max_work_seconds": ttl,
                   "capability_ttl_seconds": ttl},
        "cleanup": ["throwaway accounts / additive rows only"],
        "stop_conditions": ["operator stop"]}


def _app(db: Path) -> BattleApplication:
    return BattleApplication(db, planner=None, live_execution_enabled=True,
                             tool_risk_registry={"http.client": "high"})


def cmd_open(a):
    run = Path(a.run_dir); run.mkdir(parents=True, exist_ok=True)
    host = _host(a.target)
    db = run / "governed.sqlite3"
    for p in (db, Path(str(db) + ".witness"), Path(str(db) + "-wal"), Path(str(db) + "-shm")):
        if p.is_dir():
            import shutil; shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink()
    B, CH = _charter(host, a.ttl)
    app = _app(db)
    app.create_battle(CH, actor_id="ben", idempotency_key="create")
    app.activate_battle(B, actor_id="ben", idempotency_key="activate",
                        expected_head=app._state(B).head_hash)
    gx = GovernedExecutor(app, B, dirty_root=run / "dirty")
    grant = _human_grant()
    witnessed = bool(grant)
    READONLY_CLASSES = {"web.recon", "net.recon"}
    approval_ref = grant if witnessed else "gate-approved-local"
    if not witnessed:
        sys.stderr.write(
            "[governed] UNWITNESSED seam: no BS2_HUMAN_APPROVAL grant present. Issuing "
            "RECON capabilities only; exploit/host.access are refused (fail-closed). Provide "
            "an ask-ben grant in BS2_HUMAN_APPROVAL to authorize exploitation.\n")
    caps = {}
    for ac in ACTION_CLASSES:
        if ac not in READONLY_CLASSES and not witnessed:
            continue   # §10.2 fail-closed: no exploit capability without a witnessed grant
        cap = gx.issue_capability(
            approval_event_id=approval_ref, action_class=ac,
            scope_hosts=(host,), ttl_seconds=a.ttl,
            # Unwitnessed seams carry the 'low' ceiling (read-only recon commands only):
            # 'readonly' was NOT a value in the executor's low|medium|high|critical risk
            # order, so it resolved to 0 and denied EVERYTHING — including the recon the
            # seam's own message promises (lab pass 1, 2026-08-25).
            request_budget=a.budget, max_risk=("high" if witnessed else "low"))
        caps[ac] = cap.capability_id
    seam = {"db": str(db), "battle": B, "host": host, "target": a.target,
            "caps": caps, "opened_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    (run / SEAM).write_text(json.dumps(seam, indent=2))
    print(json.dumps({"opened": B, "host": host, "caps": list(caps),
                      "run_dir": str(run), "target": a.target}, indent=2))


def _load(run: Path):
    seam = json.loads((run / SEAM).read_text())
    app = _app(Path(seam["db"]))
    gx = GovernedExecutor(app, seam["battle"], dirty_root=run / "dirty")
    for cid in seam["caps"].values():           # rehydrate caps + spent-counts from the ledger
        gx.load_capability(cid)
    return seam, app, gx


def cmd_exec(a):
    # Archived external engine integration is not a supported 0.2 execution
    # backend. Keeping read/report operations is useful; target execution must
    # pass through the packaged exact-approval, pinned-destination runtime.
    raise SystemExit("Legacy seam execution disabled in 0.2; use live.target_exec or bs2 check-read")
    run = Path(a.run_dir)
    # EMERGENCY STOP gate: once stopped, every dispatch is refused (fail-closed) even
    # though the ledger retains the issued capabilities. The stop marker is checked
    # BEFORE the ledger is even loaded — no work reaches the door after a stop.
    if (run / "STOP").exists():
        print("[GOVERNED STOPPED: emergency stop — outstanding capabilities invalidated]",
              file=sys.stderr)
        sys.exit(5)
    seam, app, gx = _load(run)
    argv = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    # Preserve each argv token as ONE shell word (headers/JSON bodies with spaces survive).
    # $VARs from the caller's shell are already expanded before we see them; this only stops
    # in-seam word-splitting — which also shrinks the governed path's shell-injection surface.
    cmd = " ".join(shlex.quote(t) for t in argv)
    if not cmd:
        print("no command given", file=sys.stderr); sys.exit(2)
    cap_id = seam["caps"].get(a.cls)
    if cap_id is None:
        print(f"no capability for action-class {a.cls!r} (have {list(seam['caps'])})",
              file=sys.stderr); sys.exit(2)
    wid = a.work_id or f"wo-{uuid.uuid4().hex[:10]}"
    # IMPACT GATE (Codex): risk axis orthogonal to level. Classify the command's impact and gate it
    # on BS2_RISK (readonly|safe|full, default safe). A blocked command is forced above the cap so the
    # REAL default-deny gate records a governed tool.denied — not a silent skip.
    eff_risk, imp = a.risk, "read"
    risk_ceiling = os.environ.get("BS2_RISK", "safe")
    if _impact is not None:
        imp = _impact.classify(cmd)
        if not _impact.allowed(imp, risk_ceiling):
            eff_risk = "critical"   # above the 'high' ceiling -> gate denies + records
            sys.stderr.write(f"[governed] IMPACT BLOCK: '{imp}' exceeds risk ceiling '{risk_ceiling}' -> denying\n")
    with _ledger_lock(run):
        out = gx.execute(
            capability_id=cap_id, cmd=cmd, action_class=a.cls, target=seam["host"],
            risk=eff_risk, work_order_id=wid, proposal_hash=hashlib.sha256(cmd.encode()).hexdigest(),
            executor_session_id=a.session, executor_actor_id=a.actor,
            timeout=a.timeout, success_marker=a.marker)
    # The ATTACKER is the sighted operator: it sees raw stdout. The LEDGER only has the sha.
    if out.allowed:
        raw = (run / "dirty" / f"{wid}.raw").read_bytes()
        sys.stdout.buffer.write(raw)
        sys.stderr.write(f"\n[governed] work={wid} allowed sha={out.artifact_sha256[:16]} "
                         f"marker={out.marker or '-'} dispatch={out.dispatch_event_id}\n")
        sys.exit(0)
    else:
        sys.stderr.write(f"[governed] DENIED: {out.reason} (work={wid})\n")
        sys.exit(3)


def cmd_attested(a):
    """List work_order_ids that carry a verifier attestation (provenance for reflex arming)."""
    run = Path(a.run_dir)
    seam, app, gx = _load(run)
    wids = set()
    VT = (getattr(EventType, "TOOL_VERIFIED", None), getattr(EventType, "WORK_VERIFIED", None))
    vt = tuple(x for x in VT if x is not None) + tuple(getattr(x, "value", x) for x in VT if x is not None)
    for e in app._events(seam["battle"]):
        if _etype(e) in vt:
            w = _payload(e).get("work_order_id")
            if w:
                wids.add(w)
    print(json.dumps(sorted(wids)))

def cmd_events(a):
    run = Path(a.run_dir)
    seam, app, gx = _load(run)
    events = app._events(seam["battle"])
    SENSITIVE = ("flag", "cred", "hash", "secret", "token", "password", "key")
    print(f"# governed ledger — battle {seam['battle']}  ({len(events)} events)  [MANAGER VIEW: scrubbed]")
    for e in events:
        et = getattr(e, "event_type", None) or (e.get("event_type") if isinstance(e, dict) else "?")
        pl = getattr(e, "payload", None)
        if pl is None and isinstance(e, dict):
            pl = e.get("payload", {})
        pl = pl or {}
        # scrub: never surface a value whose key looks sensitive; show key+count only
        safe = {}
        for k, v in pl.items():
            if any(s in k.lower() for s in SENSITIVE) and k.lower() not in ("artifact_sha256",):
                safe[k] = "<withheld>"
            elif k in ("proposal_hash", "artifact_sha256") and isinstance(v, str):
                safe[k] = v[:16] + "…"
            else:
                safe[k] = v
        etv = et.value if hasattr(et, "value") else et
        keys = ", ".join(f"{k}={safe[k]}" for k in
                         ("action_class", "target", "capability_id", "work_order_id",
                          "artifact_sha256", "size_bytes", "reason") if k in safe)
        print(f"  {etv:22} {keys}")


def _etype(e):
    t = getattr(e, "event_type", None)
    return t if t is not None else (e.get("event_type") if isinstance(e, dict) else None)


def _payload(e):
    pl = getattr(e, "payload", None)
    if pl is None and isinstance(e, dict):
        pl = e.get("payload", {})
    return pl or {}


def cmd_finding(a):
    """Record a foothold / solved-challenge as a GOVERNED evidence event.

    The attacker logs a short LABEL (never a secret value — the manager view scrubs
    sensitive keys, but keep labels non-sensitive by discipline). Optionally binds the
    work_order whose artifact proves it.
    """
    run = Path(a.run_dir)
    seam, app, gx = _load(run)
    # The ARTIFACT is the evidence: bind the proving work-order's sha256 into the ledger
    # (schema-pure). The human label is operator annotation, not authority -> scrubbed sidecar.
    sha = size = None
    for e in app._events(seam["battle"]):
        if _etype(e) in (EventType.TOOL_COMPLETED, EventType.TOOL_COMPLETED.value) \
                and _payload(e).get("work_order_id") == a.work_id:
            sha = _payload(e).get("artifact_sha256"); size = _payload(e).get("size_bytes")
    if sha is None:
        print(f"no tool.completed artifact for work {a.work_id!r} to back this finding",
              file=sys.stderr); sys.exit(2)
    ev_id = f"ev-{a.work_id}"
    with _ledger_lock(run):
        gx._emit(
            EventType.EVIDENCE_RECORDED,
            {"evidence_id": ev_id, "sha256": sha, "content_type": "application/octet-stream",
             "size_bytes": int(size or 0), "work_order_id": a.work_id, "target_generation": 1},
            actor_id="verifier-1", actor_role=ActorRole.VERIFIER)  # evidence attested by verifier, not executor
    with open(run / "findings.jsonl", "a") as fh:               # scrubbed operator annotation
        fh.write(json.dumps({"evidence_id": ev_id, "work_order_id": a.work_id,
                             "vuln_class": a.vuln_class, "severity": a.severity,
                             "label": a.label}) + "\n")
    print(f"[governed] evidence {ev_id} recorded (sha={sha[:16]}…) — finding: {a.label}")


def cmd_verify(a):
    """Independent, separation-of-duties verification of a work order's artifact.

    A DISTINCT verifier actor re-reads the dirty-plane artifact, re-derives the sha256,
    and confirms it matches the tool.completed receipt (tamper detection) -> tool.verified.
    """
    run = Path(a.run_dir)
    seam, app, gx = _load(run)
    claimed = None
    for e in app._events(seam["battle"]):
        if _etype(e) in (EventType.TOOL_COMPLETED, EventType.TOOL_COMPLETED.value) \
                and _payload(e).get("work_order_id") == a.work_id:
            claimed = _payload(e).get("artifact_sha256")
    if claimed is None:
        print(f"no tool.completed for work {a.work_id!r}", file=sys.stderr); sys.exit(2)
    vf = Verifier(app, seam["battle"], dirty_root=run / "dirty",
                  verifier_session_id="verifier-session", verifier_actor_id="verifier-1")
    with _ledger_lock(run):
        ok = vf.verify(work_order_id=a.work_id, claimed_sha256=claimed,
                       executor_session_id="attacker-session", executor_actor_id="pentest-agent")
    print(f"[governed] verify work={a.work_id}: {'VERIFIED' if ok else 'FAILED (tamper)'}")
    sys.exit(0 if ok else 4)


def cmd_status(a):
    """Content-blind MANAGER surface over the REAL governed ledger (replaces manager_bridge)."""
    run = Path(a.run_dir)
    seam, app, gx = _load(run)
    from collections import Counter
    c = Counter()
    denied = []
    for e in app._events(seam["battle"]):
        et = _etype(e); etv = et.value if hasattr(et, "value") else et
        c[etv] += 1
        if etv == "tool.denied":
            denied.append(_payload(e).get("reason", "?"))
    findings = []                                # human labels from the scrubbed sidecar
    fp = run / "findings.jsonl"
    if fp.exists():
        for line in fp.read_text().splitlines():
            try:
                d = json.loads(line); findings.append((d["vuln_class"], d["severity"], d["label"]))
            except Exception:
                pass
    print(f"● governed pentest — battle {seam['battle']}")
    print(f"  target {seam['target']}  host {seam['host']}  [MANAGER VIEW: content-blind]")
    print(f"  dispatched={c.get('tool.dispatched',0)} completed={c.get('tool.completed',0)} "
          f"verified={c.get('tool.verified',0)} denied={c.get('tool.denied',0)} "
          f"caps={c.get('capability.issued',0)}")
    print(f"  findings ({len(findings)}):")
    for vc, sev, label in findings:
        print(f"    - [{vc}/{sev}] {label}")
    if denied:
        print(f"  denied gates ({len(denied)}): " + "; ".join(sorted(set(denied))))


def cmd_stop(a):
    """EMERGENCY STOP: invalidate outstanding capabilities for this seam immediately.
    The STOP marker gates cmd_exec (every later dispatch refuses with exit 5). The
    ledger itself is append-only and untouched — history stays auditable, which is
    exactly what a stop must preserve."""
    run = Path(a.run_dir)
    (run / "STOP").write_text(json.dumps(
        {"ts": dt.datetime.now(dt.timezone.utc).isoformat(),
         "reason": a.reason or "operator stop"}))
    print(f"[governed] EMERGENCY STOP recorded for {run} — "
          "outstanding capabilities invalidated (exec now refuses)")


def main():
    ap = argparse.ArgumentParser(description="governed seam — sighted attacker THROUGH BS2 governance")
    sub = ap.add_subparsers(dest="c", required=True)
    o = sub.add_parser("open"); o.add_argument("--target", required=True)
    o.add_argument("--run-dir", required=True); o.add_argument("--ttl", type=int, default=21600)
    o.add_argument("--budget", type=int, default=1000); o.set_defaults(fn=cmd_open)
    e = sub.add_parser("exec"); e.add_argument("--run-dir", required=True)
    e.add_argument("--class", dest="cls", default="web.exploit")
    e.add_argument("--risk", default="high"); e.add_argument("--work-id", dest="work_id", default=None)
    e.add_argument("--marker", default=None); e.add_argument("--timeout", type=int, default=60)
    e.add_argument("--session", default="attacker-session"); e.add_argument("--actor", default="pentest-agent")
    e.add_argument("cmd", nargs=argparse.REMAINDER); e.set_defaults(fn=cmd_exec)
    v = sub.add_parser("events"); v.add_argument("--run-dir", required=True); v.set_defaults(fn=cmd_events)
    f = sub.add_parser("finding"); f.add_argument("--run-dir", required=True)
    f.add_argument("--label", required=True); f.add_argument("--class", dest="vuln_class", default="misc")
    f.add_argument("--severity", default="medium"); f.add_argument("--work-id", dest="work_id", default=None)
    f.set_defaults(fn=cmd_finding)
    vf = sub.add_parser("verify"); vf.add_argument("--run-dir", required=True)
    vf.add_argument("--work-id", dest="work_id", required=True); vf.set_defaults(fn=cmd_verify)
    s = sub.add_parser("status"); s.add_argument("--run-dir", required=True); s.set_defaults(fn=cmd_status)
    st = sub.add_parser("stop"); st.add_argument("--run-dir", required=True)
    st.add_argument("--reason", default="operator stop"); st.set_defaults(fn=cmd_stop)
    at = sub.add_parser("attested"); at.add_argument("--run-dir", required=True); at.set_defaults(fn=cmd_attested)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
