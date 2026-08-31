"""bola_slice — the P1-2 slice CORE extracted as a library (2026-08-25).

Proves the deterministic matrix against a FAKE app (no network): same-schema
cross-owner 200 is INVISIBLE to the schema oracle and is caught only by the bound
anon ownership-diff; a foreign 403 is a genuine negative; confirmation is fail-closed
(partial answers hold, one disprover rejects, full stands confirm); the ledger persists
and dedups across runs; and the run_deep_deepseek graft emits scrubbed markers only.
"""
import json
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

import bola_slice as BS            # noqa: E402
import skeptic                     # noqa: E402
from experiment_ledger import ExperimentLedger   # noqa: E402

FULL_STANDS = {key: False for key, _q in skeptic.DISPROVE_CHECKLIST}


def plan_with_tokens(tmp_path):
    """The library resolves auth ONLY from 600 token files on this host — the test
    writes real ones so the fake app sees distinct authenticated principals."""
    toks = {}
    for name, token in (("a", "tok-a"), ("b", "tok-b")):
        path = tmp_path / f"tok-{name}"
        path.write_text(token)
        os.chmod(path, 0o600)
        toks[name] = str(path)
    return {
        "target": "http://fake.local",
        "endpoints": [{"id": "loc-ep", "method": "GET",
                       "route_template": "/api/vehicle/{vehicleid}/location",
                       "template_var": "vehicleid"}],
        "id_sources": {"vehicleid": {"route_template": "/api/vehicle/vehicles",
                                     "list_field": "vehicles", "field": "uuid"}},
        "principals": [
            {"principal": "user:a", "auth": {"token_file": toks["a"]}, "refs": {}},
            {"principal": "user:b", "auth": {"token_file": toks["b"]}, "refs": {}},
        ],
    }


def fake_app_runner(foreign_status=200):
    """Two principals: a owns veh-1, b owns veh-2. Cross-owner GET returns the SAME
    schema (blind to the schema oracle) or a 403 (genuine negative); anon is 401."""
    def runner(spec):
        principal = (spec.get("principal") or "").split(":")[-1]
        authed = bool((spec.get("headers") or {}).get("Authorization"))
        route = spec.get("route_template", "")
        binding = spec.get("path_binding") or {}
        if route.endswith("/vehicles"):
            return {"status": 200, "headers": {"content-type": "application/json"},
                    "schema_keys": ["vehicles"], "ms": 5,
                    "body": json.dumps({"vehicles": [
                        {"id": 1, "uuid": "veh-1"} if principal == "a"
                        else {"id": 2, "uuid": "veh-2"}]})}
        if "vehicleid" in binding:
            if not authed:
                return {"status": 401, "headers": {}, "schema_keys": [], "ms": 2,
                        "body": "unauthorized"}
            owner = ((binding["vehicleid"] == "veh-1" and principal == "a")
                     or (binding["vehicleid"] == "veh-2" and principal == "b"))
            if not owner:
                # cross-owner: 200 with the IDENTICAL schema/body (the live crAPI shape
                # — the schema oracle is structurally blind to this; only the bound anon
                # ownership-diff sees it) or an explicit 403 refusal (genuine negative)
                if foreign_status == 403:
                    return {"status": 403, "headers": {}, "schema_keys": [],
                            "ms": 2, "body": "{}"}
                return {"status": 200, "headers": {"content-type": "application/json"},
                        "schema_keys": ["fullName", "location"], "ms": 5,
                        "body": json.dumps({"location": "A-home", "fullName": "Alice"})}
            # owner x own object — identical schema to the cross-owner response
            return {"status": 200, "headers": {"content-type": "application/json"},
                    "schema_keys": ["fullName", "location"], "ms": 5,
                    "body": json.dumps({"location": "A-home", "fullName": "Alice"})}
        return {"status": 404, "headers": {}, "schema_keys": [], "ms": 2, "body": ""}
    return runner


# ---- the matrix -------------------------------------------------------------

def test_ownership_diff_catches_same_schema_bola(tmp_path):
    """Cross-owner 200 with IDENTICAL schema: the schema oracle sees nothing; the
    bound anon probe (401 -> bola) + foreign authed 200 is the only evidence. Both
    principal directions are candidates (the live crAPI slice proved 2/2)."""
    result = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner())
    assert result["object_ids"]["user:a"]["vehicleid"] == ["veh-1"]
    assert result["object_ids"]["user:b"]["vehicleid"] == ["veh-2"]
    assert len(result["findings"]) == 2
    for rec in result["findings"]:
        d = rec.response_delta
        assert d["candidate"] == "BOLA"
        assert d["ownership_verdict"] == "bola"
        assert d["foreign_object_fields_returned"] == []  # schema oracle is blind here
        assert rec.validate() == []
        assert rec.kind == "hypothesis" and rec.confirmation_status == "unconfirmed"
        assert rec.evidence and all(e.startswith("telemetry:") for e in rec.evidence)


def test_foreign_403_is_genuine_negative(tmp_path):
    result = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner(foreign_status=403))
    assert result["findings"] == []
    assert any("candidate=None" in row for row in result["rows"])


# ---- confirmation (fail-closed) ---------------------------------------------

def test_confirm_partial_answers_hold_unconfirmed(tmp_path):
    result = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner(), skeptic_answers={"intentional_public": False})
    rec = result["findings"][0]
    assert rec.confirmation_status == "unconfirmed"       # incomplete checklist holds
    assert "held" in rec.response_delta
    assert rec.validate() == []


def test_confirm_full_stands_confirms(tmp_path):
    result = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner(), skeptic_answers=FULL_STANDS)
    rec = result["findings"][0]
    assert rec.confirmation_status == "confirmed"
    assert rec.kind == "finding" and rec.reproducible is True
    assert rec.validate() == []


def test_confirm_single_disprover_rejects(tmp_path):
    answers = dict(FULL_STANDS, response_cached=True)
    result = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner(), skeptic_answers=answers)
    rec = result["findings"][0]
    assert rec.confirmation_status == "rejected"
    assert rec.response_delta.get("disproved_by") == ["response_cached"]


# ---- the no-repeat ledger ---------------------------------------------------

def test_ledger_persists_and_dedups_across_runs(tmp_path):
    with tempfile.TemporaryDirectory() as td:
        runner = fake_app_runner()
        r1 = BS.run_slice(plan_with_tokens(tmp_path), runner, ledger_dir=td)
        assert len(r1["findings"]) == 2
        # a NEW library call (fresh process semantics) reloads the ledger and skips
        r2 = BS.run_slice(plan_with_tokens(tmp_path), runner, ledger_dir=td)
        assert r2["findings"] == []
        assert any("already tested" in row for row in r2["rows"])


def test_shared_ledger_instance_dedups_in_process(tmp_path):
    ledger = ExperimentLedger()
    r1 = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner(), ledger_dir=ledger)
    r2 = BS.run_slice(plan_with_tokens(tmp_path), fake_app_runner(), ledger_dir=ledger)
    assert len(r1["findings"]) == 2 and r2["findings"] == []


# ---- the run_deep_deepseek graft --------------------------------------------

def test_slice_plan_for_extracts_template_var():
    import run_deep_deepseek as RDD
    plan = RDD.slice_plan_for("/identity/api/v2/vehicle/{vehicleid}/location")
    assert plan["endpoints"][0]["template_var"] == "vehicleid"
    assert plan["id_sources"]["vehicleid"]["field"] == "uuid"
    assert plan["principals"] == []                        # filled by _fire_slice


def test_slice_principals_write_600_token_files(monkeypatch, tmp_path):
    import run_deep_deepseek as RDD
    monkeypatch.setattr(RDD, "RUN_DIR", str(tmp_path))
    principals = RDD._slice_principals(["tok-A", "tok-B"], str(tmp_path))
    assert [p["principal"] for p in principals] == ["user:pt1", "user:pt2"]
    for i, p in enumerate(principals, start=1):
        path = p["auth"]["token_file"]
        assert open(path).read() == f"tok-{chr(64 + i)}"
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_fire_slice_returns_scrubbed_markers(monkeypatch, tmp_path):
    import run_deep_deepseek as RDD
    monkeypatch.setattr(RDD, "RUN_DIR", str(tmp_path))
    calls = {}

    def fake_run_slice(plan, runner, **kw):
        calls["plan"] = plan
        calls["kw"] = kw
        from observation import ObservationRecord
        rec = ObservationRecord(
            target=plan["target"],
            endpoint=plan["endpoints"][0], principal="user:pt2",
            map_node="ep-bola", control_request={"control": "req-c"},
            modified_request={"test": "req-t"},
            response_delta={"candidate": "BOLA", "ownership_verdict": "bola"},
            tool={"name": "lab-slice", "version": "1"},
            evidence=["telemetry:1"], confidence="medium")
        return {"findings": [rec], "briefs": ["BRIEF"], "rows": ["[slice] x: control=200"],
                "object_ids": {}}

    import bola_slice as BS_mod
    monkeypatch.setattr(BS_mod, "run_slice", fake_run_slice)
    out = RDD._fire_slice(dict(plan_with_tokens(tmp_path), principals=[]), tokens=["SECRET-TOK"])
    assert out["status"] == "ok"
    assert out["candidates"] == [{"endpoint": "/api/vehicle/{vehicleid}/location",
                                  "principal": "user:pt2", "verdict": "BOLA"}]
    assert out["briefs_n"] == 1 and out["denied"] == 0
    blob = json.dumps(out) + json.dumps(calls["plan"])
    assert "SECRET-TOK" not in blob                   # scrubbed markers only
    assert calls["plan"]["principals"]                # filled from tokens
    # ONE no-repeat ledger per run dir (2026-08-25): the slice lane dedups across
    # lane invocations and across runs
    assert calls["kw"].get("ledger_dir") == str(tmp_path)


def test_run_htb_wires_one_experiment_ledger_per_run():
    """run_htb opens ONE ExperimentLedger per run dir, attaches it to the cartographer
    (every experiment lane consults it) and saves it at the end (source-level pin — the
    suite's established pattern for main()-wiring)."""
    import run_htb
    src = open(run_htb.__file__).read()
    assert "from experiment_ledger import ExperimentLedger" in src
    assert "C.experiment_ledger = ExperimentLedger.open(run_dir)" in src
    assert "C.experiment_ledger.save()" in src


def test_experiment_ledger_open_loads_or_creates(tmp_path):
    from experiment_ledger import ExperimentLedger
    # fresh dir -> empty ledger, records nothing
    L1 = ExperimentLedger.open(str(tmp_path))
    assert L1.records == {}
    L1.record("fp-1", {"delta": {"candidate": None}, "was_execution_error": False,
                       "map_version": 1})
    L1.save()
    # reopen -> the SAME state comes back (the shared-lane contract)
    L2 = ExperimentLedger.open(str(tmp_path))
    assert "fp-1" in L2.records
    assert L2.classify_prior("fp-1") == "genuine_negative"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
