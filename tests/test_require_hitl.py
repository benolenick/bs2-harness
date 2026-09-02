"""BS2_REQUIRE_HITL — 'HITL cannot be skipped' invariant for the governed door.

An operator who wants human-in-the-loop on EVERY command sets BS2_REQUIRE_HITL=1.
The door must then fail closed unless the full approval path is wired, instead of
silently running ungoverned when a policy/broker env var was forgotten.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "live"))
import target_exec as TE  # noqa: E402

_HITL_ENV = ("BS2_REQUIRE_HITL",) + TE._HITL_ENV


def _clear(monkeypatch):
    for k in _HITL_ENV + ("BS2_SEAM_RUN", "GB_GOVERNED_HOST", "TROOPER_EXEC_SSH"):
        monkeypatch.delenv(k, raising=False)


def test_require_hitl_blocks_when_unwired(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("BS2_REQUIRE_HITL", "1")
    # policy / broker / token all missing
    out = TE.run("echo should-not-run", target="127.0.0.1", action_class="web.recon")
    assert "should-not-run" not in out
    assert out.startswith("[target-exec BLOCKED:")
    assert "BS2_REQUIRE_HITL is set but per-command approval is not wired" in out
    for name in TE._HITL_ENV:
        assert name in out  # names the exact missing env vars for the operator


def test_require_hitl_blocks_when_partially_wired(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("BS2_REQUIRE_HITL", "1")
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", "/tmp/whatever.json")
    monkeypatch.setenv("BS2_GOVERNANCE_BROKER_URL", "http://127.0.0.1:8129")
    # token still missing -> still fail closed
    out = TE.run("echo nope", target="127.0.0.1", action_class="web.recon")
    assert out.startswith("[target-exec BLOCKED:")
    assert "BS2_GOVERNANCE_BROKER_TOKEN" in out


def test_require_hitl_off_by_default(monkeypatch):
    _clear(monkeypatch)
    # unset => legacy behaviour, the gate is transparent
    assert TE._require_hitl_gate() is None
    for falsey in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("BS2_REQUIRE_HITL", falsey)
        assert TE._require_hitl_gate() is None


def test_require_hitl_passes_gate_when_fully_wired(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("BS2_REQUIRE_HITL", "true")
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", "/tmp/whatever.json")
    monkeypatch.setenv("BS2_GOVERNANCE_BROKER_URL", "http://127.0.0.1:8129")
    monkeypatch.setenv("BS2_GOVERNANCE_BROKER_TOKEN", "tok")
    # the require-hitl precondition is satisfied; actual approval is enforced downstream
    assert TE._require_hitl_gate() is None
