"""memory_cycle — the one call the BS2 loop makes each iteration.

    slice = memory_cycle(store, frontier=[...], new_events=[...], decision=..., budget=4000)

It folds any new signal (events/decision) via the Curator, then assembles the ranked
verbatim slice via the Assembler and returns it. Fold-in and assembly stay split inside;
this is only the convenience seam so the caller needs one import and one call.
"""
from __future__ import annotations
from typing import Iterable, Optional, Sequence

from .store import CairnStore, DEFAULT_DB
from .curator import Curator
from .assembler import Assembler, ContextSlice


def memory_cycle(store: CairnStore, *, frontier: Iterable[str] = (),
                 new_events: Sequence[tuple] = (), decision: Optional[dict] = None,
                 budget: int = 4000) -> ContextSlice:
    cur = Curator(store)
    for ev in new_events:
        # ev = (seq, event_type, payload_dict)
        cur.fold_event(*ev)
    if decision:
        cur.fold_decision(
            decision["entity"], decision["content"],
            status=decision.get("status", "hypothesis"),
            source=decision.get("source"), kind=decision.get("kind", "lesson"),
            decision_id=decision.get("id"))
    return Assembler(store).build_slice(frontier=frontier, budget=budget)


def open_store(db_path: str = DEFAULT_DB) -> CairnStore:
    return CairnStore(db_path)
