from __future__ import annotations

import json
import os

from live import target_exec


def _policy(tmp_path, **changes):
    os.chmod(tmp_path, 0o700)
    value = {
        "schema_version": 1,
        "revision": 1,
        "network_mode": "scope_only",
        "allowed_hosts": ["10.10.10.0/24"],
        "max_actions_per_host": 2,
        "budget_window_seconds": 3600,
        "max_parallel_actions": 1,
        "require_human_approval": True,
        "soft_directives": [],
        "deny_delete": True,
    } | changes
    path = tmp_path / "runtime-policy.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_unsafe_policy_permissions_fail_closed(monkeypatch, tmp_path):
    path = _policy(tmp_path)
    path.chmod(0o644)
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", str(path))
    monkeypatch.setattr(target_exec, "_capture", lambda *_: (_ for _ in ()).throw(AssertionError("ran")))
    assert "policy permissions are unsafe" in target_exec.run("curl http://10.10.10.7", "10.10.10.7")


def test_any_rm_is_blocked_before_capture(monkeypatch, tmp_path):
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", str(_policy(tmp_path)))
    monkeypatch.setattr(target_exec, "_capture", lambda *_: (_ for _ in ()).throw(AssertionError("ran")))
    result = target_exec.run("rm harmless.tmp", "10.10.10.7")
    assert "BLOCKED" in result and "destructive pattern" in result


def test_network_mode_and_scope_are_enforced_before_capture(monkeypatch, tmp_path):
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", str(_policy(tmp_path, network_mode="deny")))
    monkeypatch.setattr(target_exec, "_capture", lambda *_: (_ for _ in ()).throw(AssertionError("ran")))
    assert "network mode denies" in target_exec.run("curl http://10.10.10.7", "10.10.10.7")

    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", str(_policy(tmp_path, allowed_hosts=["lab.invalid"])))
    assert "outside the configured scope" in target_exec.run("curl http://10.10.10.7", "10.10.10.7")


def test_per_host_budget_is_reserved_before_execution(monkeypatch, tmp_path):
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", str(_policy(tmp_path)))
    monkeypatch.setattr(target_exec, "_command_approval", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(target_exec, "_run_governed", lambda *_: "ok")
    assert target_exec._runtime_guard("10.10.10.7", reserve=True) is None
    assert target_exec._runtime_guard("10.10.10.7", reserve=True) is None
    assert "budget exhausted (2/2)" in target_exec._runtime_guard("10.10.10.7", reserve=True)
