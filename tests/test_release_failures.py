import json
from bs2.memory import BattleMemory
from bs2.session import check_private_read
from bs2.verification import verify_read
from live import target_exec as te
from runtime_fixture import runtime_fixture
import pytest


def test_policy_change_during_approval_blocks_contact(tmp_path, monkeypatch):
    with runtime_fixture(tmp_path) as f:
        approve = te._command_approval
        def mutate(*a, **k):
            result = approve(*a, **k)
            policy = json.loads(f["policy"].read_text()); policy["revision"] = 99
            f["policy"].write_text(json.dumps(policy))
            return result
        monkeypatch.setattr(te, "_command_approval", mutate)
        assert "policy changed after approval" in te.run("curl " + f["base"] + "/whoami", f["base"])
        assert not f["contacts"]


def test_timeout_is_inconclusive_and_unresolved_not_negative(tmp_path, monkeypatch):
    with runtime_fixture(tmp_path) as f:
        def timeout(*args): raise TimeoutError()
        monkeypatch.setattr(te.transport, "execute", timeout)
        assert "INCONCLUSIVE" in te.run("curl " + f["base"] + "/whoami", f["base"])
        state = BattleMemory(f["directory"]).panel()
        assert state["suspected"] and state["unresolved_intents"]
        assert not state["already_tried"] and not state["known"]


def test_wrong_principal_anonymous_and_missing_policy_cannot_confirm(tmp_path):
    with runtime_fixture(tmp_path) as f:
        proof = check_private_read(f["directory"], base=f["base"], route="/private/1", **f["kwargs"])
        assert proof["verdict"] == "confirmed"
        a,b,c,ai,bi = proof["receipt_seqs"]
        args = dict(owner=a, other=b, anonymous=c, owner_identity=ai, other_identity=bi,
                    resource_id="1", private_contract=f["kwargs"]["private_contract"])
        for change in ({"other_identity": ai}, {"anonymous": b}, {"resource_id": "wrong"}, {"private_contract": ""}):
            assert verify_read(f["directory"], **dict(args, **change))["verdict"] == "inconclusive"


def test_memory_identity_survives_directory_move_and_unknown_is_not_change(tmp_path):
    path = tmp_path / "old"
    memory = BattleMemory(path)
    memory.journal.append("verification", {"verdict": "negative", "reason": "synthetic", "action_key": "a", "conditions": {"generation": "g1"}})
    source = memory.panel()["already_tried"][0]["source"]
    moved = tmp_path / "moved"; path.rename(moved)
    restored = BattleMemory(moved)
    assert restored.panel()["already_tried"][0]["source"] == source
    assert restored.retry("a", {})["changed"] == []
    assert restored.retry("a", {})["unknown"] == ["generation"]
    assert not restored.retry("a", {})["suppress"]


def test_broker_rejects_replayed_nonce(tmp_path):
    import os, time, urllib.request, urllib.error
    from bs2.journal import digest
    from bs2.transport import prepare
    with runtime_fixture(tmp_path) as f:
        command = "curl " + f["base"] + "/whoami"
        body = {"command": command, "execution": prepare(command, f["base"], json.loads(f["policy"].read_text()), 2),
                "nonce": "f" * 32, "expires_at": time.time() + 10}
        body["request_digest"] = digest(body)
        request = urllib.request.Request(os.environ["BS2_GOVERNANCE_BROKER_URL"], data=json.dumps(body).encode(),
                                         headers={"X-BS2-Broker-Token": os.environ["BS2_GOVERNANCE_BROKER_TOKEN"]})
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["data"]["allowed"]
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request)
        assert exc.value.code == 409
        assert not f["contacts"]
