"""P1-4 lever auditing (re-audit 2026-08-25): the direct-file fallback follows the
INTENT -> materialize -> COMPLETION order with a hash-chained audit; a failure at any
step returns a typed indeterminate result and never a silent flat-file authority."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

import manager_bridge as MB                # noqa: E402


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MANAGER_LEVERS_DIRECT", "1")   # force the direct fallback
    rd = str(tmp_path / "atrun")
    os.makedirs(rd, exist_ok=True)
    return rd


def _audit_rows(rd):
    with open(os.path.join(rd, MB.A_LEVER_AUDIT)) as f:
        return [json.loads(ln) for ln in f]


def test_intent_then_materialize_then_completion(tmp_path, monkeypatch):
    rd = _setup(tmp_path, monkeypatch)
    out = MB.set_goal("rce_as:drupal", run_dir=rd)
    assert out["ok"] and out["via"] == "direct-file" and out["audit_head"]
    rows = _audit_rows(rd)
    assert [r["action"] for r in rows] == ["set_goal:intent", "set_goal:complete"]
    # the intent row precedes the materialized state digest in the completion row
    assert rows[1]["preview"].startswith("state " + out["audit_head"])
    # the chain links: intent.prev is empty, completion.prev is the intent hash
    assert rows[0]["prev"] == "" and rows[1]["prev"] == rows[0]["hash"]
    # the flat file the engine reads really materialized
    assert open(os.path.join(rd, MB.LEVER_GOAL)).read().strip() == "rce_as:drupal"


def test_hold_and_directives_audit_the_same_chain(tmp_path, monkeypatch):
    rd = _setup(tmp_path, monkeypatch)
    assert MB.set_hold(True, run_dir=rd)["ok"]
    assert MB.set_directives("prioritise dev.*\n", run_dir=rd)["ok"]
    assert MB.set_hold(False, run_dir=rd)["ok"]
    rows = _audit_rows(rd)
    # every row chains to its predecessor, in order
    for prev, row in zip(rows, rows[1:]):
        assert row["prev"] == prev["hash"]
    assert [r["action"] for r in rows] == [
        "set_hold:intent", "set_hold:complete",
        "set_directives:intent", "set_directives:complete",
        "set_hold:intent", "set_hold:complete"]
    assert not os.path.exists(os.path.join(rd, MB.LEVER_HOLD))   # off really removed


def test_materialize_failure_returns_indeterminate_and_fences(tmp_path, monkeypatch):
    rd = _setup(tmp_path, monkeypatch)
    # the goal path is a DIRECTORY: open(...,"w") raises IsADirectoryError (OSError)
    os.makedirs(os.path.join(rd, MB.LEVER_GOAL), exist_ok=True)
    out = MB.set_goal("root", run_dir=rd)
    assert out["ok"] is False and "indeterminate" in out["error"]
    rows = _audit_rows(rd)
    # the intent is durably recorded; NO completion row follows (the fence)
    assert [r["action"] for r in rows] == ["set_goal:intent"]
    # and the state did not silently change: the lever was NOT applied
    assert os.path.isdir(os.path.join(rd, MB.LEVER_GOAL))


def test_audit_survives_in_the_cockpit_tail(tmp_path, monkeypatch):
    rd = _setup(tmp_path, monkeypatch)
    MB.set_goal("root", run_dir=rd)
    tail = MB._lever_audit_tail(rd, n=2)
    assert [t["action"] for t in tail] == ["set_goal:intent", "set_goal:complete"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
