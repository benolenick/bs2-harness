#!/usr/bin/env python3
"""gunbelt.authoring.vocab — the LIVE join surface for recipe authoring.

A gunbelt recipe's `operator:` must name a real Ariadne OPERATOR, and its
`confirms:` / `verify.emits` tokens should name real Ariadne PREDICATES — else the
recipe 500s Ariadne's replan loop at fire time. This module reads BOTH from the live
Ariadne install (not a copy) so the gate always validates against ground truth.
"""
from __future__ import annotations
import sys, os
ARIADNE = "/home/operator/ariadne"
if ARIADNE not in sys.path:
    sys.path.insert(0, ARIADNE)

from ariadne.schema import load_predicates          # noqa: E402
from ariadne.loader import load_operators            # noqa: E402


def predicate_names() -> set:
    return set(load_predicates().keys())


def operator_names() -> set:
    return {o.name for o in load_operators()}


def predicate_arity() -> dict:
    return {n: p.arity for n, p in load_predicates().items()}


def llm_vocab_block() -> str:
    """Compact, model-facing description of every legal predicate + operator."""
    preds = load_predicates()
    ops = load_operators()
    lines = ["LEGAL PREDICATES (confirms:/emits: tokens MUST be one of these names):"]
    for p in preds.values():
        lines.append(f"  {p.name}/{p.arity} — {p.means}")
    lines.append("")
    lines.append("EXISTING OPERATORS (operator: SHOULD reuse one of these names; propose a")
    lines.append("new one only if nothing fits, and declare it):")
    for o in sorted(ops, key=lambda x: x.name):
        pre = " ".join("[" + " ".join(map(str, pt)) + "]" for pt in o.pre)
        post = " ".join("[" + " ".join(map(str, pt)) + "]" for pt in o.post)
        lines.append(f"  {o.name}: {pre} -> {post}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(f"live predicates: {len(predicate_names())}")
    print(f"live operators:  {len(operator_names())}")
