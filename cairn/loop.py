"""LoopDriver — make sense+fold UNSKIPPABLE (fix #1: autonomic, not voluntary).

The critique: the cycle only helps if the agent REMEMBERS to assemble each cycle and
REMEMBERS to fold back — the exact willpower the store was meant to remove. This driver
removes the willpower:

  - `begin()` refuses to serve the next slice until the previous cycle was `commit()`ed,
    so the loop literally cannot advance without closing the sense→act→fold arc.
  - the `cycle()` context manager auto-commits on block exit (even on exception), so a
    cycle can never be left open, and a cycle that folded NOTHING and gave no explicit
    "no change" ack is recorded as an UNFOLDED cycle (silent drift becomes visible signal,
    never a silent gap).

Usage (the shape the BS2 loop adopts):

    driver = LoopDriver(store, on_warn=print)
    while improving:
        with driver.cycle(frontier=[...], budget=4000) as ctx:
            act(ctx.slice.text)                 # reason over the served slice
            ctx.fold_event(seq, etype, payload) # … fold what you learned …
            ctx.decision("memoria", "…", status="verified", source="file:…:120")
            # if truly nothing changed: ctx.no_change("still waiting on X")
"""
from __future__ import annotations
from contextlib import contextmanager
from typing import Callable, Iterable, Optional

from .store import CairnStore
from .curator import Curator
from .assembler import Assembler, ContextSlice
from .recall import Recaller
from .provenance import now_iso


class CycleContext:
    """Handed to the agent inside a cycle; every write goes through here and is counted."""

    def __init__(self, driver: "LoopDriver", slice_: ContextSlice, frontier: list[str]):
        self.driver = driver
        self.slice = slice_
        self.frontier = frontier
        self._folds = 0
        self._ack_no_change: Optional[str] = None

    # --- fold-back surface (delegates to the Curator, counts activity) ---
    def fold_event(self, seq, event_type, payload):
        ids = self.driver.curator.fold_event(seq, event_type, payload)
        self._folds += len(ids)
        return ids

    def decision(self, entity, content, **kw):
        self._folds += 1
        return self.driver.curator.fold_decision(entity, content, **kw)

    def negative(self, entity, content, **kw):
        self._folds += 1
        return self.driver.curator.fold_negative(entity, content, **kw)

    def wire(self, engine, fires, **kw):
        self._folds += 1
        return self.driver.curator.wire_state(engine, fires, **kw)

    def verify(self, item_id, as_of=None):
        self._folds += 1
        return self.driver.store.verify(item_id, as_of)

    def no_change(self, reason: str = "no change this cycle"):
        """Explicitly acknowledge that nothing was learned — distinct from forgetting."""
        self._ack_no_change = reason

    @property
    def folded(self) -> int:
        return self._folds


class LoopDriver:
    def __init__(self, store: CairnStore, recaller: Recaller | None = None,
                 on_warn: Optional[Callable[[str], None]] = None):
        self.store = store
        self.curator = Curator(store)
        self.assembler = Assembler(store, recaller)
        self.on_warn = on_warn or (lambda m: None)
        self._open = False           # is a cycle currently open (begun, not committed)?
        self.n_cycles = 0
        self.n_unfolded = 0
        self.history: list[dict] = []

    def begin(self, frontier: Iterable[str] = (), budget: int = 4000) -> CycleContext:
        if self._open:
            raise RuntimeError(
                "cairn: previous cycle was never committed — the sense->act->fold arc must "
                "close before the next slice is served (call commit()/use the cycle() context).")
        self._open = True
        self.n_cycles += 1
        frontier = list(frontier)
        sl = self.assembler.build_slice(frontier=frontier, budget=budget)
        self._ctx = CycleContext(self, sl, frontier)
        return self._ctx

    def commit(self, ctx: Optional[CycleContext] = None) -> dict:
        if not self._open:
            raise RuntimeError("cairn: commit() with no open cycle.")
        ctx = ctx or self._ctx
        unfolded = ctx.folded == 0 and ctx._ack_no_change is None
        if unfolded:
            self.n_unfolded += 1
            self.on_warn(f"cairn: UNFOLDED cycle #{self.n_cycles} (frontier={ctx.frontier}) — "
                         f"served a slice but folded nothing and gave no no_change() ack; "
                         f"the store did not learn from this cycle.")
        rec = {"cycle": self.n_cycles, "at": now_iso(), "frontier": ctx.frontier,
               "folds": ctx.folded, "unfolded": unfolded,
               "no_change": ctx._ack_no_change, "shed": ctx.slice.stats.get("shed_count", 0)}
        self.history.append(rec)
        self._open = False
        self._ctx = None
        return rec

    @contextmanager
    def cycle(self, frontier: Iterable[str] = (), budget: int = 4000):
        ctx = self.begin(frontier=frontier, budget=budget)
        try:
            yield ctx
        finally:
            # auto-commit even on exception, so a cycle can never be left open (unskippable)
            self.commit(ctx)

    def health(self) -> dict:
        return {"cycles": self.n_cycles, "unfolded": self.n_unfolded,
                "fold_rate": round(1 - self.n_unfolded / self.n_cycles, 3) if self.n_cycles else None,
                "store": self.store.stats()}
