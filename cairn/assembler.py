"""Assembler — the read half of the loop: build the one slice served each cycle.

Encodes om-d6's ranked spec, now with the three hardenings from the design critique:

  #2 relevance: selection is Recaller-scored (lexical overlap + value + recency), not entity
      substring — a relevant fact surfaces even if its entity name doesn't string-match.
  #3 budget: TIERED packing with an explicit, LOGGED shed list — invariants are inviolable,
      the rest is packed by tier then score to the budget, and nothing is dropped silently
      (silent truncation reads as "covered everything" when it didn't).
  #4 staleness + contradiction: an item older than its kind's TTL is served [stale] (re-verify
      before trusting); a contradicting singleton fact is served [!contested], never as [ok].

Section order (om-d6): invariants → wired-vs-orphaned → lessons → ground-truth facts →
open threads → tool surface. Load-bearing items are served VERBATIM (never re-summarised).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

from .store import CairnStore, Item
from .provenance import age_label, age_seconds
from .recall import Recaller

# per-kind time-to-stale (seconds); None = never stale. Signals re-verify, does not delete.
TTL_BY_KIND = {
    "invariant": None, "lesson": 30 * 86400, "wired_state": 6 * 3600,
    "flag": 7 * 86400, "credential": 7 * 86400, "host": 7 * 86400, "fact": 7 * 86400,
    "thread": 24 * 3600, "tool": 7 * 86400, "negative": 30 * 86400, "event": 3 * 86400,
}

# tiers control packing order + which sections are inviolable
TIER = {
    "invariant": 0,
    "wired_state": 1, "lesson": 1,
    "flag": 2, "credential": 2, "host": 2, "fact": 2,
    "thread": 3,
    "tool": 4, "negative": 4, "event": 4,
}

SECTION_OF = {
    "invariant": "## 1 · NORTH-STAR + INVARIANTS",
    "wired_state": "## 2 · WIRED vs ORPHANED",
    "lesson": "## 3 · DISTILLED LESSONS",
    "flag": "## 4 · GROUND-TRUTH FACTS", "credential": "## 4 · GROUND-TRUTH FACTS",
    "host": "## 4 · GROUND-TRUTH FACTS", "fact": "## 4 · GROUND-TRUTH FACTS",
    "thread": "## 5 · OPEN THREADS",
    "tool": "## 6 · TOOL SURFACE", "negative": "## · DEAD MOVES (do not retry)",
    "event": "## · EVENTS",
}
SECTION_ORDER = ["## 1 · NORTH-STAR + INVARIANTS", "## 2 · WIRED vs ORPHANED",
                 "## 3 · DISTILLED LESSONS", "## 4 · GROUND-TRUTH FACTS",
                 "## 5 · OPEN THREADS", "## 6 · TOOL SURFACE",
                 "## · DEAD MOVES (do not retry)", "## · EVENTS"]


def toks(s: str) -> int:
    return max(1, len(s) // 4)


def is_stale(it: Item) -> bool:
    ttl = TTL_BY_KIND.get(it.kind)
    if ttl is None:
        return False
    age = age_seconds(it.as_of)
    return age is not None and age > ttl


def _stamp(it: Item, contested: set[int]) -> str:
    if it.id in contested:
        tag = "!  "        # contradiction: two live truths — do NOT trust as fact
    elif is_stale(it):
        tag = "stale"      # past its TTL — re-verify before acting
    elif it.verified:
        tag = "ok "
    else:
        tag = "hyp"
    src = f"  <{it.source}>" if it.source else ""
    return f"  [{tag}] ({age_label(it.as_of)}) {it.content}{src}"


@dataclass
class ContextSlice:
    text: str
    sections: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def __str__(self):
        return self.text


class Assembler:
    def __init__(self, store: CairnStore, recaller: Recaller | None = None):
        self.store = store
        self.recaller = recaller or Recaller()

    def build_slice(self, frontier: Iterable[str] = (), budget: int = 4000) -> ContextSlice:
        frontier = list(frontier)
        pool = self.store.live()
        contested = self.store.conflicts()

        # score every item; stale items take a penalty so they shed first but still flag if kept
        scored: list[tuple[Item, float, int]] = []
        for it in pool:
            s = self.recaller.score(frontier, it)
            if is_stale(it):
                s *= 0.4
            scored.append((it, s, TIER.get(it.kind, 4)))

        # pack by tier, then by score, to the budget. tier 0 (invariants) is inviolable.
        chosen: list[Item] = []
        shed: list[str] = []
        used = 0
        for tier in sorted(set(t for _, _, t in scored)):
            tier_items = sorted([(it, s) for it, s, t in scored if t == tier],
                                key=lambda x: x[1], reverse=True)
            for it, _s in tier_items:
                line_cost = toks(_stamp(it, contested)) + 1
                if tier == 0 or used + line_cost <= budget:
                    chosen.append(it)
                    used += line_cost
                else:
                    shed.append(f"{it.kind}:{it.entity}")

        # render chosen items grouped into ordered sections
        buckets: dict[str, list[Item]] = {}
        for it in chosen:
            buckets.setdefault(SECTION_OF.get(it.kind, "## · EVENTS"), []).append(it)
        for sec in buckets:
            buckets[sec].sort(key=lambda i: (-i.value, i.content))

        out: list[str] = []
        sections: dict[str, list[str]] = {}
        for sec in SECTION_ORDER:
            if sec in buckets:
                lines = [sec] + [_stamp(i, contested) for i in buckets[sec]]
                sections[sec] = lines
                out.extend(lines)
                out.append("")

        text = "\n".join(out).rstrip() + "\n"
        n_inv = sum(1 for it in chosen if it.kind == "invariant")
        stats = {
            "slice_tokens": toks(text), "budget": budget, "items": len(chosen),
            "sections": len(sections), "shed": shed, "shed_count": len(shed),
            "protected_over_budget": (n_inv > 0 and used > budget),
            "stale_kept": sum(1 for it in chosen if is_stale(it)),
            "contested": len([i for i in chosen if i.id in contested]),
        }
        return ContextSlice(text=text, sections=sections, stats=stats)
