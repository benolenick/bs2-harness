import json
import socket
import sqlite3
import threading
import urllib.request
import pytest
from bs2 import transport
from bs2.approval import validate_request
from bs2.journal import digest
from bs2.memory import BattleMemory
from bs2.session import check_private_read
from bs2.verification import verify_read
from bs2.panel import server
from live import target_exec as te
from runtime_fixture import runtime_fixture


def test_controlled_proof_negative_memory_restart_and_condition_change(tmp_path):
    with runtime_fixture(tmp_path) as f:
        result = check_private_read(f["directory"], base=f["base"], route="/private/1", **f["kwargs"])
        assert result["verdict"] == "confirmed"
        negative = check_private_read(f["directory"], base=f["base"], route="/guarded/1", **f["kwargs"])
        assert negative["verdict"] == "negative"
        count = len(f["contacts"])
        repeat = check_private_read(f["directory"], base=f["base"], route="/guarded/1", **f["kwargs"])
        assert repeat["verdict"] == "suppressed" and len(f["contacts"]) == count
        reopened = check_private_read(f["directory"], base=f["base"], route="/guarded/1", **dict(f["kwargs"], generation="fixture-v2"))
        assert reopened["verdict"] == "negative" and len(f["contacts"]) == count + 5
        memory = BattleMemory(f["directory"])
        state = memory.panel()
        assert state["already_tried"] and state["known"]
        assert all("fixture-owner-token" not in json.dumps(r) for r in memory.journal.events())
        assert all(i["source"].startswith(memory.entity + ":event:") for i in state["known"])
        first = memory.fold(); n = first.stats()["total_rows"]; first.close()
        second = memory.fold(); assert second.stats()["total_rows"] == n; second.close()


def test_missing_controls_and_model_verdict_cannot_verify(tmp_path):
    memory = BattleMemory(tmp_path)
    memory.journal.append("hypothesis", {"claim": "verified=true marker-only finding"})
    assert memory.panel()["suspected"] and not memory.panel()["known"]
    result = verify_read(tmp_path, owner=1, other=1, anonymous=1, owner_identity=1, other_identity=1,
                         resource_id="1", private_contract="private")
    assert result["verdict"] == "inconclusive"
    assert not memory.retry("anything", {})["suppress"]


@pytest.mark.parametrize("command", ["bash -c 'curl http://127.0.0.1'", "curl -L http://127.0.0.1", "curl http://127.0.0.1 http://192.0.2.1", "curl --proxy http://192.0.2.1 http://127.0.0.1", "curl -H 'Host: other' http://127.0.0.1", "curl --data @/etc/passwd http://127.0.0.1", "curl http://127.0.0.1;id"])
def test_transport_rejects_bypasses(command):
    with pytest.raises(ValueError):
        transport.prepare(command, "127.0.0.1", {"network_mode": "loopback_only", "allowed_ports": [80]}, 5)


def test_approval_mutation_and_expiry_are_rejected():
    import time
    body = {"nonce": "a" * 32, "expires_at": time.time() + 10, "execution": {"backend": "pinned-http-v1"}, "command": "curl a"}
    body["request_digest"] = digest(body)
    assert validate_request(body)
    body["command"] = "curl b"
    assert not validate_request(body)
    body["expires_at"] = time.time() - 1
    body["request_digest"] = digest({k: v for k, v in body.items() if k != "request_digest"})
    assert not validate_request(body)


def test_no_uncontained_fallback_or_missing_binding(tmp_path, monkeypatch):
    with runtime_fixture(tmp_path) as f:
        monkeypatch.setattr(te, "_capture", lambda *_: pytest.fail("shell escaped"))
        assert "containment unavailable" in te.run("echo nope", f["base"])
        monkeypatch.setattr(te, "_command_approval", lambda *a, **k: None)
        assert "missing or expired exact approval receipt" in te.run("curl " + f["base"] + "/whoami", f["base"])
        assert not f["contacts"]


def test_redirect_and_forged_status(tmp_path):
    with runtime_fixture(tmp_path) as f:
        out = te.run("curl " + f["base"] + "/redirect", f["base"])
        assert "__GB_STATUS__:302" in out and len(f["contacts"]) == 1
        out = te.run("curl " + f["base"] + "/forged", f["base"])
        from live.governed_runner import parse_response
        assert parse_response(out)["status"] == 403
        assert te._GOVERNANCE_CONTEXT.last_receipt["payload"]["status"] == 403


def test_no_second_dns_lookup(tmp_path, monkeypatch):
    with runtime_fixture(tmp_path) as f:
        plan = transport.prepare("curl " + f["base"] + "/whoami", f["base"], json.loads(f["policy"].read_text()), 3)
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("second DNS lookup"))
        assert transport.execute(plan)[1]["status"] == 403


def test_journal_integrity_and_isolation(tmp_path):
    a, b = BattleMemory(tmp_path / "a"), BattleMemory(tmp_path / "b")
    for mem in (a, b): mem.journal.append("hypothesis", {"claim": "candidate"})
    assert a.panel()["suspected"][0]["source"] != b.panel()["suspected"][0]["source"]
    with sqlite3.connect(a.journal.db) as con: con.execute("UPDATE events SET payload='{}' WHERE seq=1")
    with pytest.raises(ValueError, match="integrity"): a.context()


def test_panel_exact_context_read_only_and_origin_guard(tmp_path):
    memory = BattleMemory(tmp_path)
    memory.journal.append("hypothesis", {"claim": "<script>alert(1)</script>"})
    context = memory.context()
    srv = server(tmp_path, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}"
        with urllib.request.urlopen(url + "/api/state") as r: assert json.load(r)["context"]["text"] == context["text"]
        with urllib.request.urlopen(url + "/api/event/1") as r: assert json.load(r)["kind"] == "hypothesis"
        with pytest.raises(urllib.error.HTTPError): urllib.request.urlopen(url + "/api/event/../../etc/passwd")
        with pytest.raises(urllib.error.HTTPError): urllib.request.urlopen(urllib.request.Request(url + "/api/state", headers={"Host": "evil.invalid"}))
        with pytest.raises(urllib.error.HTTPError): urllib.request.urlopen(url + "/api/state", data=b"{}")
    finally:
        srv.shutdown(); srv.server_close()
