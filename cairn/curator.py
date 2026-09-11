"""Curator — the fold-in half of the loop (split from assembly, per recon gap #3).

The Curator is the ONLY writer. It takes new signal — a BS2 event, a durable decision,
or a dead move — sanitizes it, and folds it into the store append-only + idempotent.
It never assembles or summarises; that is the Assembler's job. Keeping these apart is
what lets "curate" and "reason over a slice" be measured (and swapped) independently.
"""
from __future__ import annotations
from typing import Optional

from .store import CairnStore, STATE, HISTORY, NEGATIVE
from .sanitize import project_event, assert_safe
from .provenance import now_iso


class Curator:
    def __init__(self, store: CairnStore):
        self.store = store

    def fold_event(self, seq: int, event_type: str, payload: dict) -> list[int]:
        """Sanitize a battle_event and fold its metadata facts. Idempotent by event seq."""
        ids = []
        for sf in project_event(seq, event_type, payload):
            assert_safe(sf.content)
            content = sf.content
            if sf.value_ref and sf.kind in ("flag", "credential"):
                # keep the answer-key value with the label, still metadata (no exploit body)
                content = f"{sf.content} = {sf.value_ref}"
            ids.append(self.store.fold(
                sf.entity, content, sf.kind, layer=STATE,
                status="verified",  # an event on the append-only causal log is ground truth
                source=sf.source, fold_key=f"{sf.source}:{sf.kind}:{sf.entity}"))
        return ids

    def fold_decision(self, entity: str, content: str, *, status: str = "hypothesis",
                      source: Optional[str] = None, kind: str = "lesson",
                      as_of: Optional[str] = None, decision_id: Optional[str] = None) -> int:
        """Fold a durable decision/lesson. Append-only; tagged hypothesis|verified (INV-6).

        Precedence the consumer must honour stays: live-file > folded > summary — so a lesson
        that names a file is a POINTER to re-check, not a replacement for reading it.
        """
        assert_safe(content)
        return self.store.fold(entity, content, kind, layer=STATE, status=status,
                               source=source, as_of=as_of,
                               fold_key=(f"decision:{decision_id}" if decision_id else None))

    def fold_negative(self, entity: str, content: str, *, source: Optional[str] = None) -> int:
        """A dead move / disproven lane. The negatives layer is load-bearing (anti-thrash)."""
        assert_safe(content)
        return self.store.fold(entity, content, "negative", layer=NEGATIVE,
                               status="verified", source=source)

    def supersede(self, old_id: int, entity: str, content: str, *, kind: str,
                  status: str = "verified", source: Optional[str] = None) -> int:
        """State-preserving update: fold the new item, then point the old one at it."""
        new_id = self.store.fold(entity, content, kind, status=status, source=source,
                                 as_of=now_iso())
        if new_id != old_id:
            self.store.supersede(old_id, new_id)
        return new_id

    def set_wired(self, engine: str, state: str, *, note: Optional[str] = None,
                  source: Optional[str] = None) -> int:
        """Fold/refresh an engine's wiring state with a rich label (FIRES/ADVISORY/REFLEX/
        ORPHANED). Supersedes any prior live wired_state so the table shows one truth."""
        content = f"{engine} -> {state}" + (f"  ({note})" if note else "")
        prior = self.store.live(entity=engine, kind="wired_state")
        new_id = self.store.fold(engine, content, "wired_state", status="verified",
                                 source=source, as_of=now_iso())
        for p in prior:
            if p.id != new_id:
                self.store.supersede(p.id, new_id)
        return new_id

    def wire_state(self, engine: str, fires: bool, *, source: Optional[str] = None) -> int:
        """Fold/refresh a wired-vs-orphaned boolean for a BS2 engine (om-d6's #2 need).

        Supersedes any prior live wired_state for the engine so the table never shows two
        truths — the boolean changes as the agent patches, and a summary flattens it to prose.
        """
        content = f"{engine} -> {'FIRES' if fires else 'ORPHANED'}"
        prior = [i for i in self.store.live(entity=engine, kind="wired_state")]
        new_id = self.store.fold(engine, content, "wired_state", status="verified",
                                 source=source, as_of=now_iso())
        for p in prior:
            if p.id != new_id:
                self.store.supersede(p.id, new_id)
        return new_id
