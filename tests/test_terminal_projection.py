"""P1-6 terminal projections + P1-1 events-as-authority rebuild (re-audit 2026-08-25).

terminal_projection: exactly one closed state derived from the SAME coverage report
every consumer reads — assessment_complete / closure_complete / stopped_incomplete;
missing scope blocks both complete states; a forced stop is never a complete-variant.

rebuild_from_events: cartography.json is a DISPOSABLE export — rebuild it from the
canonical telemetry.jsonl event stream + map.json; a corrupt event aborts the replay
before anything is saved (consumers never advance past the event head they processed).
"""
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "live"))
sys.path.insert(0, str(HERE / "manager"))

import cartographer as CG                                   # noqa: E402
import cartographer.hypotheses as HYP                       # noqa: E402
from cartographer.coverage import (TERMINAL_STATES,         # noqa: E402
                                   terminal_projection)

TARGET = "fixture.local"


def _map_doc(port=80):
    return {"target": TARGET,
            "hosts": [{"ip": TARGET,
                       "ports": [{"port": port, "name": "http",
                                  "product": "nginx", "version": "1.0"}]}]}


def _cart(tmp_path):
    d = tmp_path / "cart"; d.mkdir()
    c = CG.Cartographer(str(d))
    (d / "map.json").write_text(json.dumps(_map_doc()))
    c.ingest_map_json(0)
    return c


def _complete(c):
    """Mark every ritual of every node done via the fold control vocabulary — the
    deterministic path to a coverage-complete map. Iterates because completing the
    host opens the INTERIOR frontier (identity/privesc/netview/localenum), whose
    rituals must be enumerated too."""
    for _ in range(6):
        folds = [f"enum={nid}:{r}" for nid, n in c.doc["nodes"].items()
                 for r in c._rituals_for(n) if r not in (n.get("rituals_done") or [])]
        if not folds:
            break
        c.fold(folds, ts=2)
    assert c.coverage_report()["blockers"] == []
    return c


def _scope():
    return {"hosts": [TARGET]}


def _hyp(c):
    nid = next(iter(c.doc["nodes"]))
    return HYP.raise_hypothesis(
        c.doc, node=nid, vuln_class="bola", locus=TARGET, title="fixture bola",
        raised_from=["manager"], confidence="low",
        required_validation=HYP.required_validation_for_class("bola"),
        impact="Potential bola impact.", severity="medium", ts=1)


# ---- P1-6 terminal projections -------------------------------------------------------

def test_terminal_vocabulary_is_closed():
    assert TERMINAL_STATES == ("assessment_complete", "closure_complete",
                               "stopped_incomplete")


def test_missing_scope_blocks_complete_states(tmp_path):
    c = _complete(_cart(tmp_path))
    for scope in (None, {}, {"hosts": []}):
        proj = c.terminal_projection(scope=scope)
        assert proj["projection"] is None and "blocked" in proj["reason"]


def test_incomplete_projects_stopped_incomplete(tmp_path):
    c = _cart(tmp_path)                     # rituals never run -> coverage blockers
    proj = c.terminal_projection(scope=_scope())
    assert proj["projection"] == "stopped_incomplete"
    assert proj["reason"]                   # names the blockers, never silent


def test_forced_stop_is_never_a_complete_variant(tmp_path):
    c = _complete(_cart(tmp_path))          # complete map, but the run was STOPPED
    proj = c.terminal_projection(scope=_scope(), stopped=True)
    assert proj["projection"] == "stopped_incomplete"
    assert "forced" in proj["reason"]


def test_assessment_complete(tmp_path):
    c = _complete(_cart(tmp_path))
    proj = c.terminal_projection(scope=_scope())
    assert proj["projection"] == "assessment_complete"
    assert proj["reason"] == "scope covered, hypotheses resolved, cleanup discharged"


def test_finding_without_evidence_blocks_complete(tmp_path):
    c = _complete(_cart(tmp_path))
    hid = _hyp(c)
    c.resolve_hypothesis(hid, "confirmed", [], "no evidence", 2)
    proj = c.terminal_projection(scope=_scope())
    assert proj["projection"] == "stopped_incomplete"
    assert "verified evidence" in proj["reason"]


def test_closure_complete_requires_remediation_and_retest(tmp_path):
    c = _complete(_cart(tmp_path))
    hid = _hyp(c)
    # assessment stage: evidence-backed confirmation -> assessment_complete only
    c.set_testing(hid, 2, "proof accepted")
    fid = c.resolve_hypothesis(hid, "confirmed", ["telemetry:1"], "proof", 2)
    assert fid
    assert c.terminal_projection(scope=_scope())["projection"] == "assessment_complete"
    # closure stage: the retest outcome closes the lifecycle
    c.retest_finding(fid, "fixed", note="retest clean", ts=3)
    proj = c.terminal_projection(scope=_scope())
    assert proj["projection"] == "closure_complete"


# ---- P1-1 events are the authority; the file is a disposable export -------------------

def test_rebuild_from_events_restores_the_map(tmp_path):
    # reference: built by direct operations (the live loop path)
    ref_dir = tmp_path / "ref"; ref_dir.mkdir()
    ref = CG.Cartographer(str(ref_dir))
    (ref_dir / "map.json").write_text(json.dumps(_map_doc()))
    ref.ingest_map_json(0)
    ref.fold(["ports=80", "web80=nginx 1.0"], ts=1)
    nid = next(iter(ref.doc["nodes"]))
    hid = HYP.raise_hypothesis(
        ref.doc, node=nid, vuln_class="bola", locus=TARGET, title="fixture bola",
        raised_from=["manager"], confidence="low",
        required_validation=HYP.required_validation_for_class("bola"),
        impact="Potential bola impact.", severity="medium", ts=1)
    ref.set_testing(hid, 3, "replayed from events")
    ref.resolve_hypothesis(hid, "confirmed", ["telemetry:1"], "proof", 3)
    ref.save(3)

    # the canonical event stream (the shapes run_htb.emit writes)
    run_dir = tmp_path / "rebuild"; run_dir.mkdir()
    (run_dir / "map.json").write_text(json.dumps(_map_doc()))
    (run_dir / "telemetry.jsonl").write_text("\n".join(json.dumps(row) for row in [
        {"seq": 1, "event": "boot", "step": 0},
        {"seq": 2, "event": "ran", "step": 1,
         "folded_facts": ["ports=80", "web80=nginx 1.0"]},
        {"seq": 3, "event": "hypothesis_raised", "step": 1, "hypothesis_id": hid,
         "node": nid, "vuln_class": "bola", "locus": TARGET, "title": "fixture bola",
         "confidence": "low",
         "required_validation": HYP.required_validation_for_class("bola"),
         "severity": "medium", "impact": "Potential bola impact.",
         "raised_from": ["manager"]},
        {"seq": 4, "event": "verdict", "step": 3, "hypothesis_id": hid,
         "verdict": "confirmed", "evidence_refs": ["telemetry:1"], "reason": "proof"},
        {"seq": 5, "event": "final", "step": 3, "projection": "assessment_complete"},
    ]) + "\n")

    rebuilt = CG.Cartographer.rebuild_from_events(str(run_dir))
    assert rebuilt.doc["nodes"] == ref.doc["nodes"]
    assert rebuilt.doc["hypotheses"] == ref.doc["hypotheses"]
    assert rebuilt.doc["findings"] == ref.doc["findings"]
    # the disposable-export claim: delete the cache, rebuild again, same content
    (run_dir / "cartography.json").unlink()
    rebuilt2 = CG.Cartographer.rebuild_from_events(str(run_dir))
    assert rebuilt2.doc["nodes"] == ref.doc["nodes"]
    assert rebuilt2.doc["findings"] == ref.doc["findings"]


def test_rebuild_aborts_on_corrupt_event_and_saves_nothing(tmp_path):
    """Projection failure must not advance any consumer past the event head: a corrupt
    hypothesis event raises and the replay saves NOTHING (the old export stays)."""
    run_dir = tmp_path / "rebuild"; run_dir.mkdir()
    (run_dir / "map.json").write_text(json.dumps(_map_doc()))
    (run_dir / "telemetry.jsonl").write_text("\n".join(json.dumps(row) for row in [
        {"seq": 1, "event": "ran", "step": 1, "folded_facts": ["ports=80"]},
        {"seq": 2, "event": "hypothesis_raised", "step": 2, "hypothesis_id": "h-bad",
         "node": "port:fixture.local:80", "vuln_class": "bola", "locus": TARGET,
         "title": "t", "confidence": "banana", "severity": "medium",
         "raised_from": ["manager"]},
    ]) + "\n")
    with pytest.raises(ValueError):
        CG.Cartographer.rebuild_from_events(str(run_dir))
    assert not (run_dir / "cartography.json").exists()   # head never advanced
