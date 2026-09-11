"""The target-free end-to-end CONTRACT test (re-audit 2026-08-25, §Required end-to-end
release test). Proves the COMPLETE canonical loop on a synthetic fixture through a REAL
governed seam — no target, no network, no LLM:

  charter -> manager objective -> trooper proposal -> policy gate -> governed synthetic
  action -> dirty artifact hashed -> independent verifier -> sanitized ObservationRecord
  -> canonical projections advance -> hypothesis -> verified proof -> report/cleanup ->
  remediation disposition + retest -> manager next objective -> Lenz projection

plus the 14 failure injections; every one must fail CLOSED (deny/marker/raise — never a
silent pass, never raw leakage). Stages whose machinery is a NAMED consolidation item in
the re-audit's implementation order are explicit skips with the reason recorded, so the
gap is enumerated rather than papered over.
"""
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "live"))
sys.path.insert(0, str(HERE / "manager"))
BS2 = os.environ.get("BS2_ENGINE_DIR", "")
if BS2:
    sys.path.insert(0, BS2)

# The capability-seam engine (`battlestation`) is NOT bundled in this repo; the HITL path is
# independent of it. Skip this seam contract suite cleanly when the package isn't importable,
# instead of erroring on a fresh clone that has no such package.
pytest.importorskip("battlestation",
                    reason="capability-seam engine not bundled; the HITL/broker path is independent")

from battlestation.service import (BattleApplication, EventConflictError,  # noqa: E402
                                   EventIntegrityError, ServiceError)
from battlestation.governed_exec import (GovernedDenied, GovernedExecutor,  # noqa: E402
                                         Verifier)
from battlestation.events import EventType                                   # noqa: E402
from battlestation.domain import ActorRole                                   # noqa: E402

import appmodel as APP                                                       # noqa: E402
import charter                                                               # noqa: E402
import lab                                                                   # noqa: E402
import skeptic                                                               # noqa: E402
from experiment_ledger import ExperimentLedger, fingerprint                  # noqa: E402
from observation import ObservationRecord                                    # noqa: E402

SEAM_PY = HERE / "live" / "governed_seam.py"
FIXTURE_HOST = "fixture.local"


# ---- fixtures: a real governed seam + a real battle at the engine level -------------

def _charter_doc(battle_id="contract-fixture-1", title="Contract fixture engagement"):
    """The charter shape the canonical engine accepts (same as governed_seam._charter)."""
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "schema_version": 1, "battle_id": battle_id, "revision": 1,
        "title": title,
        "objective": "Authorized synthetic-fixture pentest recorded as governed events",
        "mode": "authorized_assessment",
        "authorization": {
            "attestor": "contract-test", "attestor_type": "human",
            "authority_ref": "CONTRACT-TEST", "attested_at": now.isoformat(),
            "valid_from": (now - dt.timedelta(minutes=5)).isoformat(),
            "valid_until": (now + dt.timedelta(hours=6)).isoformat(),
            "signature_ref": hashlib.sha256(b"contract-test").hexdigest()},
        "scope": {"cidrs": ["192.0.2.0/24"], "hosts": [FIXTURE_HOST],
                  "excluded_cidrs": [], "excluded_hosts": [],
                  "target_generations": {FIXTURE_HOST: 1}},
        "actions": {"allowed": ["net.recon", "web.recon", "web.exploit", "host.access"],
                    "forbidden": ["impact.*"], "approval_required": ["web.exploit"]},
        "data": {"residency": "local", "raw_view_roles": ["human", "operator"],
                 "credential_refs_only": True, "artifact_retention": "battle"},
        "limits": {"max_active_troopers": 8, "max_per_target": 4096,
                   "max_requests_per_minute": 600, "max_work_seconds": 3600,
                   "capability_ttl_seconds": 3600},
        "cleanup": ["throwaway accounts / additive rows only"],
        "stop_conditions": ["operator stop"],
    }


def open_seam(run, ttl=3600, budget=100):
    r = subprocess.run([sys.executable, str(SEAM_PY), "open",
                        "--target", FIXTURE_HOST, "--run-dir", str(run),
                        "--ttl", str(ttl), "--budget", str(budget)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return run


def seam_call(sub, *args):
    r = subprocess.run([sys.executable, str(SEAM_PY), sub, "--run-dir"] + list(args),
                       capture_output=True, text=True)
    return r


def seam_exec(run, cmd, cls="web.recon", risk="low", timeout=60, work_id=None,
              marker=None):
    argv = [sys.executable, str(SEAM_PY), "exec", "--run-dir", str(run),
            "--class", cls, "--risk", risk, "--timeout", str(timeout)]
    if work_id:
        argv += ["--work-id", work_id]
    if marker:
        argv += ["--marker", marker]
    argv += ["--", "bash", "-lc", cmd]
    r = subprocess.run(argv, capture_output=True, text=True)
    m = re.search(r"work=(\S+) allowed", r.stderr)
    return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr,
            "work": m.group(1) if m else None}


def engine(run):
    """The GovernedExecutor bound to the seam's real sqlite battle (engine-level checks)."""
    seam = json.loads((Path(run) / "seam.json").read_text())
    app = BattleApplication(Path(seam["db"]), planner=None,
                            live_execution_enabled=True,
                            tool_risk_registry={"http.client": "high"})
    gx = GovernedExecutor(app, seam["battle"], dirty_root=Path(run) / "dirty")
    return seam, app, gx


def events(app, battle):
    return app._events(battle)


def _etype(e):
    t = getattr(e, "event_type", None)
    return t if t is not None else (e.get("event_type") if isinstance(e, dict) else None)


def _payload(e):
    pl = getattr(e, "payload", None)
    if pl is None and isinstance(e, dict):
        pl = e.get("payload", {})
    return pl or {}


def _of_type(evs, et):
    return [e for e in evs if _etype(e) == et]


def make_battle(tmp_path, battle_id="contract-fixture-1"):
    """A fresh real battle (create + activate) at the engine level — no seam CLI."""
    app = BattleApplication(tmp_path / "b.sqlite3", planner=None,
                            live_execution_enabled=True,
                            tool_risk_registry={"http.client": "high"})
    ch = _charter_doc(battle_id=battle_id)
    app.create_battle(ch, actor_id="ben", idempotency_key="create")
    app.activate_battle(battle_id, actor_id="ben", idempotency_key="activate",
                        expected_head=app._state(battle_id).head_hash)
    return app, battle_id


def _record(evidence=None, delta=None):
    return ObservationRecord(
        target=FIXTURE_HOST,
        endpoint={"id": "ep-1", "method": "GET",
                  "route_template": "/fixture/{id}", "vhost": ""},
        principal="user:a", tenant="t1", map_node="ep-1",
        tool={"name": "lab-slice", "version": "1", "configuration": {}},
        evidence=evidence or ["telemetry:1"],
        response_delta=delta or {"candidate": "BOLA"},
        control_request={"control": "req-c-1"},
        modified_request={"test": "req-t-1"},
        confidence="medium", state_mutated=False)


def _clean_answers():
    return {key: False for key, _q in skeptic.DISPROVE_CHECKLIST}


# ---- THE CONTRACT: full canonical loop, one test, every stage asserted -----------------

def test_contract_full_loop(monkeypatch, tmp_path):
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    run = tmp_path / "seam"
    run.mkdir()

    # 1. human-attested charter gates the run (out-of-scope refusal is its own injection)
    ch = {"title": "contract fixture", "authority": "fixture-operator",
          "scope": {"hosts": [FIXTURE_HOST], "cidrs": ["192.0.2.0/24"], "ports": [80]},
          "actions": {"allowed": ["web.recon"], "forbidden": ["impact.*"]},
          "stop_conditions": ["operator stop"]}
    charter.bind_target(ch, FIXTURE_HOST)
    ok, why = charter.validate_target(ch, FIXTURE_HOST)
    assert ok, why
    assert not charter.validate_target(ch, "off.scope.local")[0]

    # 2. manager emits ONE objective (deterministic parser — no LLM in a contract test)
    import run_htb
    verb, arg = run_htb.parse_action(
        "WHY: the fixture surface was observed\n"
        "TASK Probe the synthetic fixture and confirm the marker")
    assert verb == "TASK" and "synthetic fixture" in arg
    assert run_htb.parse_rationale(
        "WHY: the fixture surface was observed\nTASK x") == "the fixture surface was observed"

    # 3-5. trooper proposes an exact action; the REAL policy gate allows it through the
    # REAL door; the governed worker executes the synthetic fixture action and the dirty
    # artifact is hashed into the ledger (the raw body NEVER enters the ledger).
    open_seam(run)
    cmd = "echo fixture-artifact-42; printf fixture-artifact-42 | sha256sum"
    res = seam_exec(run, cmd)
    assert res["rc"] == 0 and res["work"], res["stderr"]
    import shlex
    wid = res["work"]
    # the seam hashes the QUOTED argv join (bash -lc 'cmd'), not the bare command
    proposal_hash = hashlib.sha256(shlex.join(["bash", "-lc", cmd]).encode()).hexdigest()
    seam, app, gx = engine(run)
    evs = events(app, seam["battle"])
    assert _of_type(evs, EventType.CAPABILITY_ISSUED.value)
    disp = [e for e in _of_type(evs, EventType.TOOL_DISPATCHED.value)
            if _payload(e).get("work_order_id") == wid]
    comp = [e for e in _of_type(evs, EventType.TOOL_COMPLETED.value)
            if _payload(e).get("work_order_id") == wid]
    assert disp and comp
    assert comp[0].causal_event_id == disp[0].event_id   # completed is CAUSED BY dispatch
    assert _payload(disp[0]).get("proposal_hash") == proposal_hash
    raw = (run / "dirty" / f"{wid}.raw").read_bytes()
    assert _payload(comp[0]).get("artifact_sha256") == hashlib.sha256(raw).hexdigest()
    assert _payload(comp[0]).get("size_bytes") == len(raw)
    assert b"fixture-artifact-42" in raw          # the synthetic action really ran

    # 6. independent verifier checks the dirty artifact (separation of duties, tamper
    # detection) — the receipt chain is now dispatched -> completed -> verified
    v = seam_call("verify", str(run), "--work-id", wid)
    assert v.returncode == 0, v.stderr
    assert _of_type(events(app, seam["battle"]), EventType.TOOL_VERIFIED.value)

    # 7. sanitized ObservationRecord accepted (typed, fail-closed validation)
    rec = _record()
    assert rec.validate() == []
    assert rec.kind == "hypothesis" and rec.confirmation_status == "unconfirmed"

    # 8. canonical projections advance: Cartographer (discovery map) + ApplicationModel
    cart_dir = tmp_path / "cart"; cart_dir.mkdir()
    C = _cart(cart_dir)
    C.fold(["ports=80", "web80=fixture-http 1.0"], ts=1); C.save(1)
    assert C.doc["nodes"], "cartographer projection must record folded facts"
    am = APP.ApplicationModel(tmp_path / "am")
    am.fold(["endpoint=GET /fixture/{id} auth=user object_type=item"])
    assert am.version > 0 and am.templated_endpoints()

    # 9. hypothesis raised on the map
    import cartographer.hypotheses as HYP
    node_id = next(iter(C.doc["nodes"]))
    hid = HYP.raise_hypothesis(
        C.doc, node=node_id, vuln_class="BOLA", locus=FIXTURE_HOST,
        title="cross-principal fixture object read", raised_from=["manager"],
        confidence="low",
        required_validation=HYP.required_validation_for_class("BOLA"),
        impact="Potential BOLA impact if validated.", severity="medium", ts=1)
    C.save(1)
    assert hid in C.doc["hypotheses"]

    # 10. verified proof confirms the hypothesis (skeptic full checklist + typed evidence)
    out = lab.confirm(rec, skeptic_answers=_clean_answers(), allow_confirm=True)
    assert out.kind == "finding" and out.confirmation_status == "confirmed"

    # 11. report + cleanup: engagement report renders; the charter's cleanup dispositions
    # ride along; the EMERGENCY STOP closes the seam (happy-path cleanup)
    C.set_testing(hid, 2, "contract proof accepted")
    finding_id = C.resolve_hypothesis(hid, "confirmed", evidence_refs=["telemetry:1"],
                                      reason="contract proof accepted", ts=2)
    C.save(2)
    assert finding_id
    report = C.engagement_report(str(cart_dir))
    assert report["completion_statement"]
    assert ch["stop_conditions"] == ["operator stop"]
    s = seam_call("stop", str(run))
    assert s.returncode == 0 and "EMERGENCY STOP" in s.stdout
    after = seam_exec(run, "printf never-runs")
    assert after["rc"] == 5 and "GOVERNED STOPPED" in after["stderr"]

    # 12. remediation disposition + retest close the lifecycle: negatives prevent
    # equivalent repeat work; a changed map reopens the experiment
    led = ExperimentLedger(tmp_path / "ledger")
    fp = fingerprint({"endpoint_id": "ep-1", "method": "GET",
                      "principal": "user:a", "object": "item-1", "mutation": False,
                      "payload_family": "none", "oracle": "foreign_object_returned"})
    assert led.should_retest(fp, current_version=1, learns_anything_new=True)[0]
    led.record(fp, {"was_execution_error": False, "delta": {"candidate": None},
                    "map_version": 1})
    assert led.should_retest(fp, current_version=1, learns_anything_new=True) \
        == (False, "already_tested")
    assert led.should_retest(fp, current_version=2, learns_anything_new=True) \
        == (True, "map_changed")

    # 13. manager receives the result and chooses the NEXT objective (the fold cycle)
    vv, va = run_htb.parse_action(f"VERDICT {hid} confirmed: contract proof accepted")
    assert vv == "VERDICT" and "confirmed" in va
    nv, _ = run_htb.parse_action("TASK Close the remaining fixture surface")
    assert nv == "TASK"

    # 14. signed Lenz projection: structural events only, arbitrary text has NO path in
    from lenz_harness import SafeLenzStream
    lenz_dir = tmp_path / "lenz"
    lz = SafeLenzStream(lenz_dir, steps=3)
    lz.observe("coverage", step=1, pct=50.0, open_count=1, untouched_count=1,
               complete=False)
    lz.observe("manager", step=1, verb="TASK", routes=0, memoria=False)
    lz.observe("ran", step=1, secs=1.0, cmds=1, blocked=False)
    lz.observe("final", step=1)
    with pytest.raises(ValueError):
        lz.emit("arbitrary-free-text-event", note="rm -rf /")   # no route into Lenz
    lz.stop(step=1)
    with pytest.raises(RuntimeError):
        lz.emit("coverage", step=1, pct=1.0, open_count=0,
                untouched_count=0, complete=True)               # closed stream refuses
    rows = [json.loads(ln) for ln in (lenz_dir / "telemetry.jsonl").read_text().splitlines()]
    assert [r["event"] for r in rows] == ["boot", "coverage", "manager", "ran", "final", "stop"]
    assert all("fixture-artifact" not in json.dumps(r) for r in rows)


def _cart(cart_dir):
    import cartographer as CG
    return CG.Cartographer(str(cart_dir))


# ---- failure injections: each must fail CLOSED ----------------------------------------

def test_injection_stale_event_head(tmp_path):
    """A write carrying a stale expected head is refused by the engine CAS."""
    app, B = make_battle(tmp_path)
    st = app._state(B)
    base = dict(battle_id=B, event_type=EventType.CAPABILITY_ISSUED,
                payload={"capability_id": "cap-stale", "approval_event_id": "g",
                         "action_class": "web.recon", "scope": [FIXTURE_HOST],
                         "ttl_seconds": 60, "request_budget": 5, "max_risk": "low",
                         "issued_at": dt.datetime.now(dt.timezone.utc).isoformat()},
                actor_id="policy-kernel", actor_role=ActorRole.POLICY,
                charter_revision=st.charter_revision,
                charter_hash=st.charter_hash or "",
                manager_generation=st.manager_generation)
    app._append_validated(**base, expected_head=st.head_hash,
                          idempotency_key="stale-k1")
    with pytest.raises(EventConflictError, match="stale"):
        app._append_validated(**base, expected_head=st.head_hash,   # the OLD head
                              idempotency_key="stale-k2")


def test_injection_duplicate_idempotency_key_different_intent(tmp_path):
    """Reusing an idempotency key with a DIFFERENT intent is refused, never silently
    deduplicated (the engine hashes the payload and compares)."""
    app, B = make_battle(tmp_path)
    st = app._state(B)
    base = dict(battle_id=B, event_type=EventType.TOOL_DENIED,
                actor_id="policy-kernel", actor_role=ActorRole.POLICY,
                charter_revision=st.charter_revision,
                charter_hash=st.charter_hash or "",
                manager_generation=st.manager_generation,
                expected_head=st.head_hash, idempotency_key="dup-k1")
    app._append_validated(**base, payload={"work_order_id": "w-1",
                                           "reason": "intent A"})
    with pytest.raises(EventConflictError, match="idempotency"):
        app._append_validated(**base, payload={"work_order_id": "w-1",
                                               "reason": "intent B — different"})


def test_injection_expired_capability(tmp_path):
    """An expired capability is refused at the gate (deterministic injected clock)."""
    app, B = make_battle(tmp_path)
    now = [dt.datetime(2026, 8, 25, 12, 0, tzinfo=dt.timezone.utc)]
    gx = GovernedExecutor(app, B, dirty_root=tmp_path / "dirty",
                          clock=lambda: now[0])
    cap = gx.issue_capability(approval_event_id="grant-x", action_class="web.recon",
                              scope_hosts=(FIXTURE_HOST,), ttl_seconds=60,
                              request_budget=10, max_risk="low")
    assert gx.execute(capability_id=cap.capability_id, cmd="printf hi",
                      action_class="web.recon", target=FIXTURE_HOST, risk="low",
                      work_order_id="w-exp-1", proposal_hash="ph",
                      executor_session_id="contract-exec").allowed
    now[0] += dt.timedelta(seconds=61)
    out = gx.execute(capability_id=cap.capability_id, cmd="printf hi",
                     action_class="web.recon", target=FIXTURE_HOST, risk="low",
                     work_order_id="w-exp-2", proposal_hash="ph",
                     executor_session_id="contract-exec")
    assert not out.allowed and "expired" in out.reason
    assert _of_type(events(app, B), EventType.TOOL_DENIED.value)   # deny is ledgered


@pytest.mark.skip(reason="CONTRACT GAP (re-audit consolidation): target_generation is "
                          "recorded in evidence payloads but not enforced at the "
                          "executor gate — generation checks belong to the canonical "
                          "engine step 4.")
def test_injection_wrong_target_generation():
    ...


def test_injection_missing_approval_event(monkeypatch, tmp_path):
    """No human approval -> RECON-ONLY capabilities; exploit-class dispatch refused
    with no capability (the gate, not a silent downgrade)."""
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    run = tmp_path / "seam"; run.mkdir()
    open_seam(run)
    seam = json.loads((run / "seam.json").read_text())
    assert set(seam["caps"]) == {"web.recon", "net.recon"}     # no exploit caps minted
    r = seam_exec(run, "printf x", cls="web.exploit")
    assert r["rc"] == 2 and "no capability" in r["stderr"]


def test_injection_out_of_scope_destination(tmp_path):
    """A dispatch to a host outside the capability scope is refused at the gate."""
    app, B = make_battle(tmp_path)
    gx = GovernedExecutor(app, B, dirty_root=tmp_path / "dirty")
    cap = gx.issue_capability(approval_event_id="grant-x", action_class="web.recon",
                              scope_hosts=("fixture-a.local",), ttl_seconds=60,
                              request_budget=5, max_risk="low")
    out = gx.execute(capability_id=cap.capability_id, cmd="printf hi",
                     action_class="web.recon", target="fixture-b.local", risk="low",
                     work_order_id="w-scope", proposal_hash="ph",
                     executor_session_id="contract-exec")
    assert not out.allowed and "outside capability scope" in out.reason


def test_injection_request_budget_exhaustion(tmp_path):
    """The request budget is real: dispatch N+1 past the cap is refused."""
    app, B = make_battle(tmp_path)
    gx = GovernedExecutor(app, B, dirty_root=tmp_path / "dirty")
    cap = gx.issue_capability(approval_event_id="grant-x", action_class="web.recon",
                              scope_hosts=(FIXTURE_HOST,), ttl_seconds=60,
                              request_budget=2, max_risk="low")
    for i in range(2):
        assert gx.execute(capability_id=cap.capability_id, cmd="printf hi",
                          action_class="web.recon", target=FIXTURE_HOST, risk="low",
                          work_order_id=f"w-budget-{i}", proposal_hash="ph",
                          executor_session_id="contract-exec").allowed
    out = gx.execute(capability_id=cap.capability_id, cmd="printf hi",
                     action_class="web.recon", target=FIXTURE_HOST, risk="low",
                     work_order_id="w-budget-2", proposal_hash="ph",
                     executor_session_id="contract-exec")
    assert not out.allowed and "budget exhausted" in out.reason


def test_injection_worker_timeout(monkeypatch, tmp_path):
    """A worker that exceeds its timeout does NOT wedge the loop: the artifact is the
    '(timeout)' marker, the completion is ledgered, and the success marker is ABSENT
    (a timed-out run never looks like a verified success)."""
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    run = tmp_path / "seam"; run.mkdir()
    open_seam(run)
    res = seam_exec(run, "sleep 5", timeout=1, marker="SUCCESS-MARK")
    assert res["rc"] == 0 and res["stdout"].strip() == "(timeout)"
    assert "marker=-" in res["stderr"]                       # marker absent on timeout
    seam, app, gx = engine(run)
    comp = _of_type(events(app, seam["battle"]), EventType.TOOL_COMPLETED.value)
    assert comp and _payload(comp[0]).get("size_bytes") == len("(timeout)")


def test_injection_verifier_failure(monkeypatch, tmp_path):
    """Verifier failure is fail-closed: unknown work refuses, a non-distinct verifier
    is refused (separation of duties), and tampered artifacts FAIL verification."""
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    run = tmp_path / "seam"; run.mkdir()
    open_seam(run)
    unknown = seam_call("verify", str(run), "--work-id", "wo-nonexistent")
    assert unknown.returncode == 2 and "no tool.completed" in unknown.stderr

    seam, app, gx = engine(run)
    vf = Verifier(app, seam["battle"], dirty_root=run / "dirty",
                  verifier_session_id="v-sess", verifier_actor_id="v-actor")
    with pytest.raises(GovernedDenied):
        vf.verify(work_order_id="w-x", claimed_sha256="aa",
                  executor_session_id="v-sess", executor_actor_id="other")


def test_injection_artifact_tampering(monkeypatch, tmp_path):
    """An artifact altered after execution FAILS independent verification."""
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    run = tmp_path / "seam"; run.mkdir()
    open_seam(run)
    res = seam_exec(run, "printf genuine-artifact")
    wid = res["work"]
    assert seam_call("verify", str(run), "--work-id", wid).returncode == 0
    art = run / "dirty" / f"{wid}.raw"
    art.write_bytes(art.read_bytes() + b" TAMPERED")
    v = seam_call("verify", str(run), "--work-id", wid)
    assert v.returncode == 4 and "FAILED" in v.stdout
    seam, app, gx = engine(run)
    verd = _of_type(events(app, seam["battle"]), EventType.TOOL_VERIFIED.value)
    assert any(_payload(e).get("verified") is False for e in verd)


def test_injection_projection_failure_and_restart(tmp_path):
    """A projection that loses its file rebuilds from the canonical inputs (map.json +
    facts) instead of corrupting the engagement — and a restart never crashes."""
    import cartographer as CG
    cart_dir = tmp_path / "cart"; cart_dir.mkdir()
    C = CG.Cartographer(str(cart_dir))
    C.fold(["ports=80", "web80=fixture-http 1.0"], ts=1); C.save(1)
    assert C.doc["nodes"]
    (cart_dir / "cartography.json").unlink()                 # the crash
    C2 = CG.Cartographer(str(cart_dir))                      # restart: empty, no crash
    assert C2.doc["nodes"] == {}
    with open(cart_dir / "map.json", "w") as fh:
        json.dump({"target": FIXTURE_HOST,
                   "hosts": [{"ip": FIXTURE_HOST,
                              "ports": [{"port": 80, "name": "http",
                                         "product": "fixture-http", "version": "1.0"}]}]},
                  fh)
    C2.ingest_map_json(0)
    C2.fold(["web80=fixture-http 1.0"], ts=0); C2.save(0)    # rebuild from inputs
    assert C2.doc["nodes"]


def test_injection_unanswered_skeptic_checklist():
    """An incomplete skeptic checklist holds the hypothesis unconfirmed — fail-closed
    confirmation: partial answers can NEVER produce a finding."""
    rec = _record()
    out = lab.confirm(rec, skeptic_answers={"intentional_public": False},
                      allow_confirm=True)
    assert out.confirmation_status == "unconfirmed"
    assert out.response_delta["held"] and "missing" in out.response_delta


def test_injection_codex_observer_boundary(monkeypatch, tmp_path):
    """The Codex-facing surfaces are structural only: raw dirty-plane bodies never
    reach the governed event view, and the manager prompt carries sanitized markers,
    never commands or raw output."""
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    monkeypatch.setenv("GB_MANAGER_RAW", "0")
    run = tmp_path / "seam"; run.mkdir()
    open_seam(run)
    secret = "SECRET-fixture-body-99"
    res = seam_exec(run, f"printf '{secret}'")
    assert res["stdout"].startswith(secret)                  # the ATTACKER sees raw...
    ev = seam_call("events", str(run))
    assert ev.returncode == 0
    assert secret not in ev.stdout                           # ...the OBSERVER never does
    assert "tool.completed" in ev.stdout

    import run_htb
    prompt = run_htb.build_prompt(
        FIXTURE_HOST, facts=["web80=fixture-http 1.0"],
        transcript=[("TASK x", f"observed: http | facts: {secret}")],
        routes=[], recon_next=[], mem="", frontier=[], open_hypotheses=[],
        coverage={"surface": {"pct": 100.0, "untouched": []},
                  "hypotheses": {"open_count": 0}, "findings_count": 0,
                  "complete": True, "blockers": []},
        environment={}, charter_doc={
            "title": "contract", "authority": "fixture", "target": FIXTURE_HOST,
            "scope": {"cidrs": ["192.0.2.0/24"], "excluded_cidrs": []},
            "actions": {"allowed": ["web.recon"], "forbidden": ["impact.*"]},
            "stop_conditions": ["operator stop"]}, autoturret=[],
        governed={"caps": ["web.recon"], "witnessed": False})
    assert "RAW cmds" not in prompt                          # content-blind default
    assert "RECON-ONLY" in prompt                            # governed ceiling is fed


def test_injection_emergency_stop_invalidates_capabilities(monkeypatch, tmp_path):
    """Emergency stop invalidates outstanding capabilities IMMEDIATELY: every later
    dispatch refuses, while the append-only ledger stays auditable."""
    monkeypatch.delenv("BS2_HUMAN_APPROVAL", raising=False)
    run = tmp_path / "seam"; run.mkdir()
    open_seam(run)
    assert seam_exec(run, "printf before-stop")["rc"] == 0
    assert seam_call("stop", str(run), "--reason", "contract injection").returncode == 0
    after = seam_exec(run, "printf after-stop")
    assert after["rc"] == 5 and "GOVERNED STOPPED" in after["stderr"]
    st = seam_call("status", str(run))                       # ledger still auditable
    assert st.returncode == 0 and "completed=1" in st.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
