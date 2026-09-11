"""Recaller — relevance scoring for assembly (fix #2: assembly quality is the ceiling).

The old `relevant()` was entity-substring matching: a fact whose entity name doesn't
string-match the frontier never surfaced, however relevant its CONTENT. This scores every
live item against the frontier by lexical overlap over content+entity+source, fused with
the item's value and recency. It is a real improvement over substring and — critically —
it is an INTERFACE: a semantic backend (embeddings / geodesic) can replace `_lexical`
behind the same `score()` without touching the assembler.
"""
from __future__ import annotations
import math
import re
from typing import Iterable

from .store import Item
from .provenance import age_seconds

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> set[str]:
    return {t for t in _WORD.findall(s.lower()) if len(t) > 1}


def _lexical(frontier_terms: set[str], it: Item) -> float:
    """Jaccard-ish overlap of the frontier vocabulary with the item's text."""
    if not frontier_terms:
        return 0.0
    txt = _tokens(f"{it.entity} {it.content} {it.source or ''}")
    if not txt:
        return 0.0
    inter = len(frontier_terms & txt)
    if inter == 0:
        return 0.0
    return inter / math.sqrt(len(frontier_terms) * len(txt))


def _recency(it: Item, half_life_s: float = 6 * 3600) -> float:
    age = age_seconds(it.as_of)
    if age is None:
        return 0.5
    return 0.5 ** (age / half_life_s)   # 1.0 fresh -> 0.5 at one half-life


class Recaller:
    """Default lexical recaller. Swap `_lexical` for embeddings to go semantic."""

    def __init__(self, w_relevance: float = 1.0, w_value: float = 0.15, w_recency: float = 0.25):
        self.wr, self.wv, self.wrec = w_relevance, w_value, w_recency

    def score(self, frontier: Iterable[str], it: Item) -> float:
        terms: set[str] = set()
        for f in frontier:
            terms |= _tokens(f)
        rel = _lexical(terms, it)
        # value normalised to ~[0,1] (DEFAULT_VALUE tops out at 10)
        return self.wr * rel + self.wv * (it.value / 10.0) + self.wrec * _recency(it)

    def rank(self, frontier: Iterable[str], items: list[Item]) -> list[tuple[Item, float]]:
        frontier = list(frontier)
        scored = [(it, self.score(frontier, it)) for it in items]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored
