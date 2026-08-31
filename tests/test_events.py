import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

from cartographer.core import Cartographer
from events import EventLedger, rebuild_from_events


def test_event_ledger_roundtrip_with_refusal():
    run_dir = tempfile.mkdtemp()
    ledger = EventLedger(run_dir)
    cart = Cartographer(run_dir, ledger=ledger)
    cart.fold(["vhost=a.local", "vhost=b.local"], ts=1)
    cart.fold(["verified=a.local", "dead=b.local", "done=unknown.local"], ts=2)

    assert [event["seq"] for event in ledger.scan()] == list(range(1, 6))
    assert any(event["kind"] == "refuse" for event in ledger.scan())
    rebuilt = rebuild_from_events(ledger, tempfile.mkdtemp())
    for key in ("nodes", "log"):
        assert rebuilt[key] == cart.doc[key]
    assert {nid for nid, node in rebuilt["nodes"].items()
            if node["state"] != "unverified"} == {"vhost:a.local", "vhost:b.local"}


def test_event_ledger_mode_600_and_load():
    run_dir = tempfile.mkdtemp()
    ledger = EventLedger(run_dir)
    ledger.append({"ts": 1, "kind": "evidence", "payload": {"ref": "fixture:1"}})
    ledger.save()
    path = os.path.join(run_dir, "events.json")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert EventLedger.load(run_dir).scan() == ledger.scan()
