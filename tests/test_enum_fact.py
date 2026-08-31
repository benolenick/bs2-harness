"""The enum= fact is the only input path to the coverage DONE-gate.

A trooper that finished a discovery check reports it as `enum=<port>:<ritual>`.
fold() must mark that port node's ritual done, advance its lifecycle state, and
move coverage pct. Without this the map's DONE-gate can never close and the run
burns all 30 steps into done_refused (the run-738 failure, 2026-08-25).
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

from cartographer.core import Cartographer          # noqa: E402
from cartographer.coverage import surface_coverage  # noqa: E402
from cartographer.model import ENUMERATING          # noqa: E402


def _mk_doc():
    """Minimal ledger: one host with ftp on 21 AND 2121 (the substring-collision case)."""
    return {
        "target": "10.0.0.1", "updated": 0, "log": [],
        "nodes": {
            "host:10.0.0.1": {
                "id": "host:10.0.0.1", "kind": "host", "label": "10.0.0.1",
                "state": "untouched", "rituals_done": ["full-port-sweep"],
                "touched_ts": 0, "meta": {"ip": "10.0.0.1"}},
            "port:10.0.0.1:21": {
                "id": "port:10.0.0.1:21", "kind": "port", "label": "21/ftp vsftpd 3.0.3",
                "state": "untouched", "rituals_done": [], "touched_ts": 0,
                "meta": {"port": 21, "service": "ftp", "product": "vsftpd",
                         "version": "3.0.3"}},
            "port:10.0.0.1:2121": {
                "id": "port:10.0.0.1:2121", "kind": "port", "label": "2121/ftp",
                "state": "untouched", "rituals_done": [], "touched_ts": 0,
                "meta": {"port": 2121, "service": "ftp"}},
        },
    }


def _cartographer(doc):
    c = Cartographer(tempfile.mkdtemp())  # loads empty; we inject the doc, never save
    c.doc = doc
    return c


def test_enum_fact_marks_ritual_state_and_coverage():
    c = _cartographer(_mk_doc())
    before = surface_coverage(c.doc)
    changed = c.fold(["enum=21:anon-login"], ts=1)
    n = c.doc["nodes"]["port:10.0.0.1:21"]
    assert changed["rituals"] == 1
    assert n["rituals_done"] == ["anon-login"]
    assert n["state"] == ENUMERATING  # 1 of 2 ftp rituals done -> on frontier, reduced
    after = surface_coverage(c.doc)
    # done: host 1/5 + port21 1/2 + port2121 0/2 = 2/9 (vs 1/9 before)
    assert abs(before["pct"] - 100.0 * 1 / 9) < 1e-9
    assert abs(after["pct"] - 100.0 * 2 / 9) < 1e-9
    assert "21/ftp vsftpd 3.0.3" in after["enumerating"]


def test_numeric_hint_prefers_exact_port():
    c = _cartographer(_mk_doc())
    c.fold(["enum=21:anon-login"], ts=1)
    # "21" is a substring of "2121" and 2121's id is longer — the exact-port
    # preference must keep the mark on port 21
    assert c.doc["nodes"]["port:10.0.0.1:21"]["rituals_done"] == ["anon-login"]
    assert c.doc["nodes"]["port:10.0.0.1:2121"]["rituals_done"] == []


def test_duplicate_and_bogus_enum_facts_are_ignored():
    c = _cartographer(_mk_doc())
    c.fold(["enum=21:anon-login", "enum=21:anon-login", "enum=21:totally-bogus"], ts=1)
    # duplicate idempotent, bogus ritual key rejected (must not inflate coverage)
    assert c.doc["nodes"]["port:10.0.0.1:21"]["rituals_done"] == ["anon-login"]
    assert surface_coverage(c.doc)["pct"] == 100.0 * 2 / 9


if __name__ == "__main__":
    for fn in (test_enum_fact_marks_ritual_state_and_coverage,
               test_numeric_hint_prefers_exact_port,
               test_duplicate_and_bogus_enum_facts_are_ignored):
        fn()
        print(f"ok {fn.__name__}")
