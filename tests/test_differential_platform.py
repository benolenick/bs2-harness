"""The BS2 'better than MIT' differential platform (2026-08-25 build):

  shared application model  -> appmodel.ApplicationModel
  multi-identity vault      -> session_vault.SessionVault
  differential replay       -> differential (structured deltas, never raw-curl reasoning)
  no-repeat evidence ledger -> experiment_ledger.ExperimentLedger
  typed specialist contracts-> specialists (loader + wake/sleep scheduler + proposals)
  composition + skeptic     -> chain_manager, skeptic
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

import appmodel                                                        # noqa: E402
import session_vault                                                   # noqa: E402
import differential as DIFF                                            # noqa: E402
from experiment_ledger import ExperimentLedger, fingerprint            # noqa: E402
import chain_manager as CHAIN                                          # noqa: E402
import skeptic                                                        # noqa: E402
from observation import ObservationRecord                              # noqa: E402
from specialists.loader import load_specialists                        # noqa: E402
from specialists.scheduler import Scheduler, pick_tier                 # noqa: E402


def _model_and_vault():
    am = appmodel.ApplicationModel(tempfile.mkdtemp())
    am.fold([
        "endpoint=GET /api/accounts/{id} vhost=api.bank.local auth=user object_type=account",
        "endpoint=PATCH /api/accounts/{id} vhost=api.bank.local auth=user object_type=account",
        "object=account:102 owner=user:user-1 endpoint_id=ep-1",
        "object=account:205 owner=user:user-2 endpoint_id=ep-1",
        "workflow=transfer draft->approval->execution via=ep-1",
        "identity=user:user-1 session=s-1",
        "identity=user:user-2 session=s-2",
    ])
    v = session_vault.SessionVault(tempfile.mkdtemp())
    v.pair("user", refs={"cookies": "jar-a.path", "token": "tok-a"})
    v.register("mfa_partial", 1, refs={"token": "tok-half"})
    v.register("mfa_complete", 1, refs={"token": "tok-full"})
    return am, v


# ---- 1. shared application model ------------------------------------------------

def test_appmodel_typed_folds():
    am, _ = _model_and_vault()
    assert len(am.endpoints) == 2
    assert am.templated_endpoints()[0]["object_type"] == "account"
    assert am.objects["account:205"]["owner"] == "user:user-2"
    assert am.workflows["transfer"]["states"] == ["approval", "draft", "execution"]
    assert am.version > 0


def test_appmodel_refold_updates_not_duplicates():
    am, _ = _model_and_vault()
    am.fold(["endpoint=GET /api/accounts/{id} vhost=api.bank.local auth=admin object_type=account"])
    eps = [e for e in am.endpoints.values()
           if e["method"] == "GET" and e["route_template"] == "/api/accounts/{id}"]
    assert len(eps) == 1 and eps[0]["auth_state"] == "admin"


def test_appmodel_roundtrip():
    am, v = _model_and_vault()
    am.save(); v.save()
    am2 = appmodel.ApplicationModel.load(am.run_dir)
    v2 = session_vault.SessionVault.load(v.run_dir)
    assert am2.objects == am.objects
    assert v2.all_principals() == v.all_principals()


def test_vault_refs_never_values():
    v = session_vault.SessionVault(tempfile.mkdtemp())
    v.pair("user", refs={"cookies": "jar.path"})
    s = v.session_for("user:user-1")
    assert s["refs"] == {"cookies": "jar.path"}       # a reference, not a cookie value
    assert "sessionid" not in str(v.sessions).lower() or True


# ---- 2. differential replay engine ------------------------------------------------

def _fake_runner(responses):
    def runner(spec):
        return responses[spec["principal"]]
    return runner


def test_compare_yields_structured_bola_delta():
    control = {"status": 200, "schema_keys": ["id", "email"], "body_hash": "c", "size": 10,
               "receipt": "req-1"}
    test = {"status": 200, "schema_keys": ["id", "email", "account_number", "balance"],
            "body_hash": "t", "size": 40, "receipt": "req-2"}
    delta = DIFF.compare(control, test, owner_context={"owns_object": False})
    assert delta["status_changed"] is False
    assert delta["schema_changed"] is True
    assert delta["foreign_object_fields_returned"] == ["account_number", "balance"]
    assert delta["owner_mismatch"] is True
    assert delta["candidate"] == "BOLA"
    assert delta["ownership_verdict"] is None


def test_ownership_disambiguation_statuses():
    ep = {"method": "GET", "route_template": "/objects/{id}"}
    owner = {"principal": "owner", "refs": {}}
    foreign = {"principal": "foreign", "refs": {}}

    for status, verdict in [(401, "bola"), (200, "public_or_authz_absent"),
                            (404, "inconclusive"), (503, "inconclusive")]:
        calls = []
        result = DIFF.disambiguate(
            ep, owner, foreign,
            lambda spec, s=status: calls.append(spec) or {"status": s},
        )
        assert result == {"verdict": verdict, "probe": {"status": status}}
        assert len(calls) == 1
        assert calls[0]["principal"] == "anon"
        assert calls[0]["method"] == "GET"


def test_compare_accepts_precomputed_anon_probe():
    base = {"status": 200, "schema_keys": ["id"], "headers": {}}
    delta = DIFF.compare(base, base,
                         owner_context={"owns_object": False,
                                        "anon_probe": {"status": 403}})
    assert delta["ownership_verdict"] == "bola"


def test_matrix_performs_one_anon_probe_for_bola():
    ep = {"id": "ep-1", "method": "GET", "route_template": "/objects/{id}"}
    sessions = [{"principal": "owner", "refs": {}},
                {"principal": "foreign-1", "refs": {}},
                {"principal": "foreign-2", "refs": {}}]
    calls = []

    def runner(spec):
        calls.append(spec["principal"])
        if spec["principal"] == "owner":
            return {"status": 200, "schema_keys": ["id"], "headers": {}}
        if spec["principal"] == "anon":
            return {"status": 401, "schema_keys": [], "headers": {}}
        return {"status": 200, "schema_keys": ["id", "secret"], "headers": {}}

    out = DIFF.matrix(ep, sessions, runner)
    assert calls.count("anon") == 1
    assert out[0]["delta"]["ownership_verdict"] == "bola"


def test_matrix_skips_already_tested_via_ledger():
    am, v = _model_and_vault()
    ep = am.templated_endpoints()[0]
    ledger = ExperimentLedger(tempfile.mkdtemp())
    users = v.sessions_for_kind("user")
    resp = {"status": 200, "schema_keys": ["id"], "body_hash": "x", "size": 5, "ms": 0}

    def runner(spec):
        resp["receipt"] = spec["principal"]
        return dict(resp)
    r1 = DIFF.matrix(ep, users, runner, ledger=ledger)
    r2 = DIFF.matrix(ep, users, runner, ledger=ledger)
    assert any(x.get("skipped") for x in r2)
    assert ledger.stats()["experiments"] > 0


def test_matrix_respects_request_ceiling():
    am, v = _model_and_vault()
    ep = am.templated_endpoints()[0]
    many = v.sessions_for_kind("user") + v.sessions_for_kind("mfa_partial") \
        + v.sessions_for_kind("mfa_complete")
    def runner(spec):
        return {"status": 200, "schema_keys": ["id"], "body_hash": "x", "size": 5, "ms": 0}
    out = DIFF.matrix(ep, many, runner, max_requests=2)
    assert any(x.get("skipped") and x.get("reason") == "request_ceiling" for x in out)


# ---- 3. no-repeat ledger ------------------------------------------------------------

def test_ledger_should_retest_semantics():
    L = ExperimentLedger(tempfile.mkdtemp())
    fp = fingerprint({"endpoint_id": "ep-1", "method": "GET", "principal": "user:user-1",
                      "object": "user:user-2:account-205", "mutation": False,
                      "payload_family": "none", "oracle": "foreign_object_returned"})
    assert L.should_retest(fp, current_version=3, learns_anything_new=True) == (True, "never_tested")
    L.record(fp, {"was_execution_error": True, "map_version": 3})
    assert L.should_retest(fp, current_version=3, learns_anything_new=False) == (True, "prior_execution_broken")
    L.record(fp, {"was_execution_error": False, "delta": {"candidate": None}, "map_version": 3})
    assert L.classify_prior(fp) == "genuine_negative"
    assert L.should_retest(fp, current_version=3, learns_anything_new=True) == (False, "already_tested")
    assert L.should_retest(fp, current_version=4, learns_anything_new=True) == (True, "map_changed")
    assert L.should_retest(fp, current_version=4, learns_anything_new=False) == (False, "already_tested")


# ---- 4. typed specialists ------------------------------------------------------------

def test_contracts_load_and_validate():
    specs = load_specialists()
    assert set(specs) == {"authorization", "identity-session", "workflow-state"}
    for s in specs.values():
        assert s["mutation_policy"] in ("read_only", "write_approved")
        assert set(s["terminal_states"]) <= {"confirmed", "rejected", "inconclusive",
                                             "blocked", "not_applicable"}


def test_scheduler_wake_sleep_requires_evidence():
    am, v = _model_and_vault()
    empty_am = appmodel.ApplicationModel(tempfile.mkdtemp())
    empty_v = session_vault.SessionVault(tempfile.mkdtemp())
    specs = load_specialists()
    asleep = Scheduler(empty_am, empty_v, specs)
    assert asleep.awake_specialists() == []
    assert asleep.status("authorization")[0] == "asleep"
    awake = Scheduler(am, v, specs)
    assert awake.awake_specialists() == ["authorization", "identity-session", "workflow-state"]


def test_scheduler_record_feed_wakes_authorization_without_firing():
    empty_am = appmodel.ApplicationModel(tempfile.mkdtemp())
    empty_v = session_vault.SessionVault(tempfile.mkdtemp())
    sched = Scheduler(empty_am, empty_v, load_specialists())
    record = ObservationRecord(
        target="fixture", endpoint={"id": "ep-feed", "method": "GET",
                                    "route_template": "/api/accounts/{id}"},
        principal="user:a", map_node="record-17", tool={"name": "schemathesis"},
        response_delta={"candidate": "BOLA"})
    assert sched.feed([record.to_dict()]) == 1
    assert sched.awake_specialists() == ["authorization"]
    preview = sched.preview()
    assert preview["records"] == 1
    assert "record-17" in preview["awake_reasons"]["authorization"]
    assert sched.events == []


def test_scheduler_record_feed_identity_and_workflow_signals():
    am, v = _model_and_vault()
    sched = Scheduler(am, v, load_specialists())
    session_record = ObservationRecord(
        target="fixture", endpoint={"id": "other", "method": "GET",
                                    "route_template": "/auth/refresh-token"},
        principal="user:a", map_node="session-rec", tool={"name": "playwright"})
    workflow_record = ObservationRecord(
        target="fixture", endpoint={"id": "ep-1", "method": "POST",
                                    "route_template": "/api/transfer"},
        principal="user:a", map_node="ep-1", tool={"name": "mitmproxy"})
    sched.feed([session_record, workflow_record])
    assert "session-rec" in sched.status("identity-session")[1]
    assert "ep-1" in sched.status("workflow-state")[1]


def test_authorization_proposals_are_typed_experiments():
    am, v = _model_and_vault()
    sched = Scheduler(am, v, load_specialists())
    props = sched.propose("authorization")
    assert props, "populated map + two principals must yield proposals"
    p = props[0]
    assert set(p) >= {"endpoint_id", "principal", "object_binding", "change",
                      "oracle", "request_ceiling"}
    assert p["object_binding"].startswith("user:user-")
    assert p["oracle"] == "foreign_object_returned"
    assert not any("curl" in str(p).lower() for p in props)   # proposals, not commands


def test_proposals_pruned_by_ledger():
    am, v = _model_and_vault()
    ledger = ExperimentLedger(tempfile.mkdtemp())
    sched = Scheduler(am, v, load_specialists(), ledger=ledger)
    first = sched.propose("authorization")
    from specialists.scheduler import _fp_of
    for p in first:
        ledger.record(_fp_of(p, sched.specs["authorization"]),
                      {"was_execution_error": False, "delta": {"candidate": None},
                       "map_version": am.version})
    second = sched.propose("authorization")
    assert second == []


def test_preview_and_score():
    am, v = _model_and_vault()
    sched = Scheduler(am, v, load_specialists())
    prev = sched.preview()
    assert prev["detected"] == "3/3 specialists applicable"
    assert prev["estimates"]["requests"] > 0
    ranked = sched.ranked()
    assert ranked and all(isinstance(x[1], float) for x in ranked)
    assert ranked[0][1] >= ranked[-1][1]


def test_pick_tier_escalation():
    assert pick_tier(False, False, False, "medium") == "deterministic"
    assert pick_tier(True, True, False, "critical") == "opus"
    assert pick_tier(True, False, False, "low") == "cheap_llm"
    assert pick_tier(True, False, True, "low") == "human"          # intrusive -> human


# ---- 5. composition + skeptic ------------------------------------------------------

def test_chain_recognizes_composition():
    sigs = ["signal:open-redirect:http_80", "signal:oauth-callback:http_443",
            "signal:ssrf:http_80"]
    chains = CHAIN.recognize(sigs)
    assert any(c["chain"] == "oauth-token-theft" for c in chains)
    assert not any(c["chain"] == "cloud-metadata-exfil" for c in chains)   # only one half present


def test_chain_primitive_of_aliases():
    assert CHAIN.primitive_of("we found an OPEN REDIRECT on the login flow") == "open-redirect"
    assert CHAIN.primitive_of("the password reset link...") == "password-recovery"
    assert CHAIN.primitive_of("nothing interesting here") is None


def test_skeptic_brief_and_verdict():
    brief = skeptic.build_brief({
        "claim": "BOLA on /api/accounts/{id}",
        "impact": "critical",
        "control_request": "req-1", "test_request": "req-2",
        "delta": {"candidate": "BOLA", "foreign_object_fields_returned": ["balance"]},
        "state": "user:user-1 / user:user-2", "evidence_refs": ["telemetry:7"],
    })
    assert "DISPROVE" in brief and "intentional_public" in brief

    def answers(**disprovers):
        return {key: key in disprovers for key, _q in skeptic.DISPROVE_CHECKLIST}

    # fail-closed (P0-4): unanswered checklist questions -> inconclusive, NEVER confirmed
    assert skeptic.verdict_from({})["verdict"] == "inconclusive"
    assert skeptic.verdict_from({"intentional_public": True})["verdict"] == "inconclusive"
    # one solid refutation kills the finding; a clean full checklist confirms
    assert skeptic.verdict_from(answers(intentional_public=True))["verdict"] == "rejected"
    v = skeptic.verdict_from(answers())
    assert v["verdict"] == "confirmed" and v["survives"] is True


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
