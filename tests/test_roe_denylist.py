"""RoE denylist_extra — add-only operator blocklist enforced at the governed door.

The Rules-of-Engagement wizard writes `denylist_extra` into the policy; the door must block any
command matching one of those patterns, WITHOUT ever weakening the hardcoded destructive floor.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "live"))
import target_exec as TE  # noqa: E402


def _policy(tmp_path, denylist, monkeypatch):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"network_mode": "loopback_only", "allowed_hosts": [],
                             "max_actions_per_host": 5, "budget_window_seconds": 3600,
                             "denylist_extra": denylist}))
    os.chmod(p, 0o600)
    monkeypatch.setenv("BS2_GOVERNANCE_POLICY", str(p))
    return p


def test_denylist_extra_blocks_matching_command(tmp_path, monkeypatch):
    _policy(tmp_path, ["userdel", r"DROP\s+TABLE"], monkeypatch)
    assert TE._denylist_extra_block("userdel bob") == "RoE denylist (userdel)"
    assert TE._denylist_extra_block("mysql -e 'DROP TABLE users'").startswith("RoE denylist")
    assert TE._denylist_extra_block("curl http://x/") is None


def test_denylist_extra_literal_when_not_regex(tmp_path, monkeypatch):
    # a malformed regex must still block as a literal substring (never silently ignored)
    _policy(tmp_path, ["a[b"], monkeypatch)
    assert TE._denylist_extra_block("echo a[b") == "RoE denylist (a[b)"


def test_denylist_absent_policy_is_noop(monkeypatch):
    monkeypatch.delenv("BS2_GOVERNANCE_POLICY", raising=False)
    assert TE._denylist_extra_block("anything") is None


def test_destructive_floor_survives_empty_denylist(tmp_path, monkeypatch):
    # an empty operator denylist must NOT weaken the always-on destructive guard
    _policy(tmp_path, [], monkeypatch)
    assert TE._denylist_extra_block("rm -rf /tmp/x") is None      # not in RoE list
    assert TE._blocked("rm -rf /tmp/x") is not None               # but the floor still blocks it
