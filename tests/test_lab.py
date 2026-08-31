"""The BS2 HTTP Laboratory (2026-08-25): the ONE typed adapter record, one normalizer
per tool, the replay->compare->hypothesize->confirm pipeline, and the policy gates
(sqlmap/nuclei/restler/schemathesis/zap/interactsh)."""
import json
import os
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

from observation import ObservationRecord                      # noqa: E402
from adapters import ADAPTERS, adapt                           # noqa: E402
import adapters.burp as BURP                                   # noqa: E402
import adapters.interactsh as INTER                            # noqa: E402
import adapters.playwright as PW                               # noqa: E402
import adapters.restler as RESTLER                             # noqa: E402
import adapters.schemathesis as SCHEMA                         # noqa: E402
import adapters.zap as ZAP                                     # noqa: E402
import differential as DIFF                                    # noqa: E402
import lab                                                    # noqa: E402
import skeptic                                                # noqa: E402
import appmodel as APP                                          # noqa: E402
import session_vault as VAULT                                   # noqa: E402


def _ctx():
    return {"target": "198.51.100.10", "vhost": "api.bank.local", "principal": "anon"}


def _model_vault():
    am = APP.ApplicationModel(tempfile.mkdtemp())
    am.fold([
        "endpoint=GET /api/accounts/{id} vhost=api.bank.local auth=user object_type=account",
        "identity=user:user-1 session=s-1",
        "identity=user:user-2 session=s-2",
    ])
    v = VAULT.SessionVault(tempfile.mkdtemp())
    v.pair("user", refs={"cookies": "jar.path"})
    return am, v


def _record(**kw):
    base = dict(target="198.51.100.10", endpoint={"id": "e1", "method": "GET",
               "route_template": "/api/accounts/{id}", "vhost": "api.bank.local"},
               principal="anon", map_node="unmapped", tool={"name": "nuclei"})
    base.update(kw)
    return ObservationRecord(**base)


# ---- the typed record ---------------------------------------------------------

def test_record_validation_fail_closed():
    r = ObservationRecord(target="t", endpoint={}, principal="anon", map_node="x", tool={})
    problems = r.validate()
    assert problems
    assert any("endpoint" in p for p in problems)
    assert any("tool" in p for p in problems)


def test_record_roundtrip():
    r = _record(tenant="t1", evidence=["telemetry:1"], confidence="medium",
                response_delta={"candidate": "BOLA"}, dom_diff={"hidden": "x"})
    assert ObservationRecord.from_dict(r.to_dict()).to_dict() == r.to_dict()


def test_scanner_cannot_emit_confirmed():
    r = _record()
    assert r.kind == "hypothesis" and r.confirmation_status == "unconfirmed"
    r.confirmation_status = "confirmed"
    problems = r.validate()
    assert any("only findings" in p for p in problems)
    assert any("evidence" in p for p in problems)


# ---- adapters -------------------------------------------------------------------

def test_registry_covers_the_nine():
    assert set(ADAPTERS) == {"nuclei", "katana", "mitmproxy", "playwright", "zap",
                             "restler", "schemathesis", "interactsh", "burp"}
    with pytest.raises(KeyError):
        adapt("nonexistent", "")


def test_nuclei_lead_not_finding():
    line = json.dumps({"template-id": "CVE-2021-44228",
                       "info": {"severity": "critical"},
                       "matched-at": "http://t:8080/login", "type": "http"})
    rec = adapt("nuclei", line, _ctx())["records"][0]
    assert rec.kind == "hypothesis"
    assert rec.confirmation_status == "unconfirmed"
    assert rec.confidence == "high"
    assert rec.tool["name"] == "nuclei"
    assert rec.endpoint["route_template"] == "/login"


def test_katana_folds_into_map():
    line = json.dumps({"request": {"method": "POST",
                                   "endpoint": "http://t:3000/api/transfers/execute"}})
    out = adapt("katana", line, _ctx())
    assert out["folds"] == ["endpoint=POST /api/transfers/execute"]
    assert out["records"][0].kind == "observation"
    assert out["records"][0].confirmation_status == "n_a"
    line2 = json.dumps({"request": {"method": "GET",
                                    "endpoint": "http://t:3000/api/accounts?user=bob&status=active"}})
    assert adapt("katana", line2, _ctx())["folds"] == [
        "endpoint=GET /api/accounts?user=bob&status=active params=user,status"]


def test_har_adapter_never_stores_header_values():
    har = json.dumps({"log": {"entries": [{
        "request": {"method": "GET", "url": "http://t/api/accounts/205",
                    "headers": [{"name": "Cookie", "value": "sessionid=SECRET123"},
                                {"name": "Accept", "value": "application/json"}]},
        "response": {"status": 200, "headers": [],
                     "content": {"text": "{\"id\":205}"}}}]}})
    rec = adapt("mitmproxy", har, _ctx())["records"][0]
    assert rec.control_request["method"] == "GET"
    assert rec.control_request["header_names"] == ["accept", "cookie"]
    assert "SECRET123" not in json.dumps(rec.to_dict())


def test_playwright_isolated_contexts():
    cfg = PW.capture_config(["user:user-1", "user:user-2"], ["api.bank.local"], "/tmp/x")
    assert [c["principal"] for c in cfg["contexts"]] == ["user:user-1", "user:user-2"]
    assert all(c["storage_state"].startswith("vault://") for c in cfg["contexts"])


def test_burp_schema_and_ingest():
    schema = json.load(open(BURP.SCHEMA_PATH))
    assert set(schema["required"]) >= {"target", "endpoint", "principal",
                                       "map_node", "tool", "kind", "confirmation_status"}
    wire = json.dumps({"records": [_record().to_dict()]})
    assert len(adapt("burp", wire, _ctx())["records"]) == 1
    # invalid external records fail closed — dropped, never guessed
    assert adapt("burp", json.dumps({"records": [{"target": "t"}]}), _ctx())["records"] == []


# ---- policy gates ---------------------------------------------------------------

def test_restler_gates():
    ok, _ = RESTLER.gate({"spec": "openapi.json", "mutation_policy": "write_approved"})
    assert ok
    bad, why = RESTLER.gate({"spec": "openapi.json"})
    assert not bad and "write_approved" in why
    bad, why = RESTLER.gate({"spec": "openapi.json", "mutation_policy": "write_approved",
                             "aggressive": True})
    assert not bad and "unlock" in why
    bad, why = RESTLER.gate({})
    assert not bad and "spec" in why


def test_schemathesis_gate_requires_spec():
    bad, why = SCHEMA.gate({})
    assert not bad and "spec" in why
    ok, _ = SCHEMA.gate({"spec": "openapi.json"})
    assert ok


def test_zap_passive_first_and_active_gated():
    ok, _ = ZAP.gate({})
    assert ok
    blocked, why = ZAP.gate({"active": True})
    assert not blocked and "unlock" in why
    passive = ZAP.automation_yaml("http://t", "/tmp/x", active=False)
    assert "passiveScan-config" in passive
    assert "activeScan" not in passive
    active = ZAP.automation_yaml("http://t", "/tmp/x", active=True)
    assert "activeScan" in active


def test_interactsh_self_hosted_only():
    assert not INTER.assert_self_hosted("x.oast.fun")
    assert INTER.assert_self_hosted("oob.banktest.local")
    with pytest.raises(ValueError):
        INTER.adapt("", {"callback_domain": "x.oast.fun"})


def test_sqlmap_gate_hypothesis_required():
    assert lab.SQLMAP_POLICY["spray"] == "never"
    assert lab.SQLMAP_POLICY["extraction"] == "never by default"
    assert not lab.injection_hypothesis_present([])
    lead = _record(response_delta={"candidate": "sqli"})
    assert lab.injection_hypothesis_present([lead])


# ---- differential: the status/header/JSON/DOM/timing comparison -----------------

def test_compare_header_and_timing_deltas():
    control = {"status": 200, "schema_keys": ["id"],
               "headers": {"X-Rate-Limit": "100"}, "ms": 10, "receipt": "r1"}
    test = {"status": 200, "schema_keys": ["id"],
            "headers": {"X-Rate-Limit": "100", "Set-Cookie": "s=1"}, "ms": 80,
            "receipt": "r2"}
    d = DIFF.compare(control, test)
    assert d["header_delta"] == ["set-cookie"]
    assert d["security_headers_changed"] == ["set-cookie"]
    assert d["timing_delta"]["flag"] is True
    assert "s=1" not in json.dumps(d)          # header VALUES never stored


# ---- the Laboratory pipeline ------------------------------------------------------

def test_lab_pipeline_end_to_end():
    am, v = _model_vault()
    rec = _record(principal="user:user-2", tenant="t1", evidence=["telemetry:7"],
                  endpoint={"id": "nuclei:x", "method": "GET",
                            "route_template": "/api/accounts/{id}",
                            "vhost": "api.bank.local"})

    def runner(spec):
        if spec["principal"] == "anon":
            return {"status": 200, "schema_keys": ["id", "email"], "ms": 5}
        return {"status": 200, "schema_keys": ["id", "email", "balance"], "ms": 5}

    out = lab.run(rec, am, v, runner=runner)
    assert out.map_node == "ep-1"                       # record bound to the map node
    assert out.response_delta.get("candidate")          # a hypothesis emerged
    assert out.response_delta.get("control_request")    # receipts ride along
    # stage 6 — fully answered skeptic + typed evidence + the manager's lever -> confirmed
    answers = {key: False for key, _q in skeptic.DISPROVE_CHECKLIST}
    out = lab.confirm(out, skeptic_answers=answers, allow_confirm=True)
    assert out.kind == "finding"
    assert out.confirmation_status == "confirmed"


def test_lab_skeptic_disprove_rejects():
    rec = _record(evidence=["telemetry:1"], response_delta={"candidate": "BOLA"})
    answers = {key: key == "intentional_public"
               for key, _q in skeptic.DISPROVE_CHECKLIST}
    out = lab.confirm(rec, skeptic_answers=answers, allow_confirm=True)
    assert out.confirmation_status == "rejected"
    assert out.response_delta["disproved_by"] == ["intentional_public"]


def test_confirm_holds_on_incomplete_skeptic():
    rec = _record(evidence=["telemetry:1"], response_delta={"candidate": "BOLA"})
    out = lab.confirm(rec, skeptic_answers={"intentional_public": False},
                      allow_confirm=True)
    assert out.confirmation_status == "unconfirmed"     # fail-closed, never confirmed
    assert out.response_delta["held"] and "missing" in out.response_delta


def test_confirm_rejects_untyped_evidence():
    rec = _record(evidence=["i looked at it"], response_delta={"candidate": "BOLA"})
    answers = {key: False for key, _q in skeptic.DISPROVE_CHECKLIST}
    out = lab.confirm(rec, skeptic_answers=answers, allow_confirm=True)
    assert out.confirmation_status == "unconfirmed"
    assert out.response_delta["refused_confirm"]


def test_confirm_requires_lever_and_evidence():
    rec = _record(response_delta={"candidate": "BOLA"})
    assert lab.confirm(rec, {}, allow_confirm=False).confirmation_status == "unconfirmed"
    assert lab.confirm(rec, {}, allow_confirm=True).confirmation_status == "unconfirmed"


def test_lab_invalid_record_rejected_not_confirmed():
    am, v = _model_vault()
    rec = ObservationRecord(target="t", endpoint={}, principal="anon",
                            map_node="x", tool={})
    out = lab.run(rec, am, v)
    assert out.confirmation_status == "rejected"
    assert out.response_delta.get("rejected") is True


def test_lab_observe_stage1():
    am = APP.ApplicationModel(tempfile.mkdtemp())
    v = VAULT.SessionVault(tempfile.mkdtemp())
    line = json.dumps({"request": {"method": "GET",
                                   "endpoint": "http://t:3000/api/transfers"}})
    records = lab.observe("katana", line, _ctx(), am, v)
    assert records[0].kind == "observation"
    assert records[0].map_node.startswith("ep-")       # folded into the shared model
    assert "GET" in [e["method"] for e in am.endpoints.values()]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
