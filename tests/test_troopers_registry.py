import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

import chain_manager
import troopers


def test_roster_validates_all_41_entries():
    assert troopers.validate() == []
    assert len(troopers.TROOPERS) + len(troopers.DEAD_WEIGHT) == 41


def test_active_primitives_have_complete_chain_coverage():
    assert {row["primitive"] for row in troopers.TROOPERS} <= chain_manager.PRIMITIVES
    assert all(row["primitive"] is None for row in troopers.DEAD_WEIGHT)


def test_registry_has_no_runnable_methods():
    for row in troopers.TROOPERS + troopers.DEAD_WEIGHT:
        assert isinstance(row, dict)
        assert not ({"run", "fire", "execute", "dispatch"} & set(row))
        assert all(not callable(value) for value in row.values())
