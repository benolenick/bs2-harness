"""Evidence-gate + exact-attribution + honest-completion fixes — the five builds taken
from MAP_PIPELINE_CRITICISM.md (2026-08-25), P0 acceptance items 2/4/5/8/10/11/14:

1. Outcome-gated receipts: a command that failed, was blocked, or timed out never closes
   an enum=/attack= ritual (invocation != completed enumeration).
2. Exact-or-unambiguous lifecycle controls: enum=/verified=/done=/dead= bind a stable
   node ID or fail closed; ambiguous/unknown hints mutate nothing and are logged.
3. Rejected hypotheses reach Ariadne as typed negatives ([vuln_class, locus]).
4. Hypothesis confirmation requires a telemetry evidence reference from THIS run.
5. Completion states are honest: objective-achieved vs exhausted-without-compromise.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

from trooper import FAIL_MARK, _derive_attack_facts, _derive_enum_facts      # noqa: E402
from cartographer.core import Cartographer                                   # noqa: E402
from cartographer.model import (DEAD, EXHAUSTED, FOOTHOLD, UNTOUCHED,        # noqa: E402
                                UNVERIFIED, _match_exact)
from cartographer.coverage import coverage_report, render                    # noqa: E402


def _mk_doc():
    return {
        "target": "10.0.0.1", "updated": 0, "log": [],
        "nodes": {
            "host:10.0.0.1": {
                "id": "host:10.0.0.1", "kind": "host", "label": "10.0.0.1",
                "state": UNTOUCHED, "rituals_done": ["full-port-sweep"],
                "touched_ts": 0, "meta": {"ip": "10.0.0.1"}},
            "port:10.0.0.1:80": {
                "id": "port:10.0.0.1:80", "kind": "port", "label": "80/http",
                "state": UNTOUCHED, "rituals_done": [], "touched_ts": 0,
                "meta": {"port": 80, "service": "http"}},
        },
    }


def _cartographer(doc):
    c = Cartographer(tempfile.mkdtemp())
    c.doc = doc
    return c


# ---- 1. outcome-gated receipts ----------------------------------------------

def test_failed_command_never_closes_enum_ritual():
    cmds = ["gobuster dir -u http://10.0.0.1:80 -w /w.txt"]
    assert _derive_enum_facts(cmds, ok_flags=[True]) == ["enum=80:dirs"]
    assert _derive_enum_facts(cmds, ok_flags=[False]) == []          # timed out -> no receipt
    assert _derive_enum_facts(cmds) == ["enum=80:dirs"]              # legacy callers ungated


def test_ok_flags_align_through_falsy_cmds():
    cmds = ["", "whatweb http://10.0.0.1:80", "gobuster vhost -u http://10.0.0.1:80 -w v.txt"]
    ok_flags = [True, False, True]
    assert _derive_enum_facts(cmds, ok_flags) == ["enum=80:vhosts"]


def test_failed_attack_never_closes_attack_ritual():
    cmds = ["searchsploit gitlab 13.10", "python3 gitlab_rce.py -t http://198.51.100.10"]
    facts = _derive_attack_facts(cmds, "", "gitlab", ok_flags=[True, False])
    assert facts == ["attack=gitlab:cve-lookup"]


def test_engine_searchsploit_label_counts_despite_failed_commands():
    # the engine-run prime chunk only lands in the transcript on lookup success, so it
    # counts even when a later exploit command failed
    facts = _derive_attack_facts(["python3 x.py -t http://198.51.100.10"],
                                 "[auto-searchsploit gitlab]\nGitLab 13.10 RCE",
                                 "gitlab", ok_flags=[False])
    assert "attack=gitlab:cve-lookup" in facts


def test_fail_mark_covers_timeout_and_block_markers():
    for bad in ("...(timeout)", "(timeout)", "[trooper scope-guard BLOCKED: loopback]",
                "[GOVERNED DENY: impact]", "[GOVERNED ERROR (fail-closed, not run): x]",
                "[target-exec BLOCKED: destructive pattern", "(error: ssh died)"):
        assert FAIL_MARK.search(bad), bad
    assert not FAIL_MARK.search("21/tcp open ftp vsftpd 3.0.3")


# ---- 2. exact-or-unambiguous lifecycle controls ------------------------------

def test_match_exact_prefers_exact_id():
    doc = _mk_doc()
    assert _match_exact(doc, "port:10.0.0.1:80") == ["port:10.0.0.1:80"]


def test_match_exact_unique_port_or_label():
    doc = _mk_doc()
    assert _match_exact(doc, "80") == ["port:10.0.0.1:80"]
    doc["nodes"]["vhost:a.local"] = {
        "id": "vhost:a.local", "kind": "vhost", "label": "a.local",
        "state": UNVERIFIED, "rituals_done": [], "touched_ts": 0, "meta": {}}
    assert _match_exact(doc, "a.local") == ["vhost:a.local"]
    assert _match_exact(doc, "A.LOCAL") == ["vhost:a.local"]     # case-insensitive label


def test_match_exact_ambiguous_fails_closed():
    doc = _mk_doc()
    doc["nodes"]["host:10.0.0.2"] = {
        "id": "host:10.0.0.2", "kind": "host", "label": "10.0.0.2",
        "state": UNTOUCHED, "rituals_done": ["full-port-sweep"], "touched_ts": 0,
        "meta": {"ip": "10.0.0.2"}}
    doc["nodes"]["port:10.0.0.2:80"] = {
        "id": "port:10.0.0.2:80", "kind": "port", "label": "80/http",
        "state": UNTOUCHED, "rituals_done": [], "touched_ts": 0,
        "meta": {"port": 80, "service": "http"}}
    # two hosts both expose port 80 -> a bare "80" is ambiguous
    assert _match_exact(doc, "80") == []
    assert _match_exact(doc, "nonexistent-thing") == []


def test_fold_refuses_ambiguous_enum_without_mutation():
    doc = _mk_doc()
    doc["nodes"]["host:10.0.0.2"] = {
        "id": "host:10.0.0.2", "kind": "host", "label": "10.0.0.2",
        "state": UNTOUCHED, "rituals_done": ["full-port-sweep"], "touched_ts": 0,
        "meta": {"ip": "10.0.0.2"}}
    doc["nodes"]["port:10.0.0.2:80"] = {
        "id": "port:10.0.0.2:80", "kind": "port", "label": "80/http",
        "state": UNTOUCHED, "rituals_done": [], "touched_ts": 0,
        "meta": {"port": 80, "service": "http"}}
    c = _cartographer(doc)
    changed = c.fold(["enum=80:dirs"], ts=1)
    assert changed["rituals"] == 0
    assert changed["refused"], "ambiguous hint must be logged, not silently dropped"
    assert all("dirs" not in (n.get("rituals_done") or [])
               for n in doc["nodes"].values() if n["kind"] == "port")


def test_fold_refuses_unknown_dead_and_logs():
    c = _cartographer(_mk_doc())
    changed = c.fold(["dead=ghost.example"], ts=1)
    assert changed["state_changes"] == []
    assert changed["refused"]
    assert any(e.get("op") == "fold-refused" for e in c.doc.get("log", []))


def test_fold_exact_id_and_unique_hint_still_work():
    c = _cartographer(_mk_doc())
    c.fold(["enum=port:10.0.0.1:80:dirs", "enum=80:tech-fingerprint"], ts=1)
    n = c.doc["nodes"]["port:10.0.0.1:80"]
    assert "dirs" in n["rituals_done"] and "tech-fingerprint" in n["rituals_done"]


def test_verified_dead_still_bind_vhosts_exactly():
    c = _cartographer(_mk_doc())
    c.fold(["vhost=a.local", "vhost=b.local"], ts=1)
    c.fold(["verified=a.local", "dead=b.local"], ts=2)
    assert c.doc["nodes"]["vhost:a.local"]["state"] == UNTOUCHED
    assert c.doc["nodes"]["vhost:b.local"]["state"] == DEAD


# ---- 3. negatives into Ariadne ------------------------------------------------

def test_confirmed_negatives_only_rejected():
    c = _cartographer(_mk_doc())
    c.doc["hypotheses"] = {
        "h1": {"status": "rejected", "vuln_class": "sql-injection", "node": "port:10.0.0.1:80"},
        "h2": {"status": "inconclusive", "vuln_class": "lfi", "node": "port:10.0.0.1:80"},
        "h3": {"status": "confirmed", "vuln_class": "auth-bypass", "node": "port:10.0.0.1:80"},
    }
    negs = c.confirmed_negatives()
    assert negs == [["sql-injection", "port:10.0.0.1:80"]]


def test_ariadne_routes_passes_negatives():
    import run_htb
    captured = {}
    class FakeRA:
        @staticmethod
        def advise_from_state(proven, apps, negatives=None, host=None, extra_facts=None):
            captured["negatives"] = negatives
            return {"goals": [], "recon_next": []}
    old_ra = run_htb.RA
    run_htb.RA = FakeRA
    try:
        c = _cartographer(_mk_doc())
        c.doc["hypotheses"] = {
            "h1": {"status": "rejected", "vuln_class": "sqli", "node": "port:10.0.0.1:80"}}
        run_htb.ariadne_routes([], "10.0.0.1", cart=c)
        assert captured["negatives"] == [["sqli", "port:10.0.0.1:80"]]
    finally:
        run_htb.RA = old_ra


# ---- 4. evidence-gated confirmation --------------------------------------------

def test_evidence_refs_valid():
    from run_htb import _evidence_refs_valid
    assert not _evidence_refs_valid([], {1, 2})                 # empty -> refused
    assert not _evidence_refs_valid(None, {1, 2})
    assert not _evidence_refs_valid(["telemetry:3"], {1, 2})    # stale -> refused
    assert not _evidence_refs_valid(["something:1"], {1})       # unknown shape -> refused
    assert not _evidence_refs_valid(["telemetry:2", "telemetry:9"], {2})   # one bad -> refused
    assert _evidence_refs_valid(["telemetry:2"], {1, 2})        # this run's seq -> ok


# ---- 5. honest completion states ------------------------------------------------

def _complete_doc(host_state=EXHAUSTED):
    doc = _mk_doc()
    doc["nodes"]["host:10.0.0.1"]["state"] = host_state
    doc["nodes"]["port:10.0.0.1:80"]["state"] = EXHAUSTED
    return doc


def test_exhausted_without_compromise_is_not_generic_success():
    rep = coverage_report(_complete_doc())
    assert rep["complete"] is True
    assert rep["objective_achieved"] is False
    assert rep["outcome"] == "exhausted_without_compromise"
    assert "exhausted WITHOUT compromise" in render(_complete_doc())


def test_foothold_means_objective_achieved():
    rep = coverage_report(_complete_doc(host_state=FOOTHOLD))
    assert rep["complete"] is True
    assert rep["objective_achieved"] is True
    assert rep["outcome"] == "objective_achieved"
    assert "objective achieved" in render(_complete_doc(host_state=FOOTHOLD))


def test_incomplete_outcome_and_no_success_word():
    rep = coverage_report(_mk_doc())       # untouched surface remains
    assert rep["complete"] is False
    assert rep["outcome"] == "incomplete"
    assert "INCOMPLETE" in render(_mk_doc())
    assert "COMPLETE —" not in render(_mk_doc())   # never the success framing


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
