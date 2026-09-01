"""Ariadne predicate schema: the controlled vocabulary the extractor speaks.

Two sources, cross-checked:
  1. predicates.yaml    — human-written name/arity/meaning (what the LLM is told).
  2. the operator corpus — every predicate actually used in pre/post/goal.

`check_coverage` warns if an operator uses a predicate the schema never declared
(so the extractor would never be told to emit it) or vice-versa. This keeps the
extractor's vocabulary honest as the corpus grows.
"""
from __future__ import annotations
import os
import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
PREDICATES_YAML = os.path.join(_HERE, "corpus", "predicates.yaml")


class Predicate:
    __slots__ = ("name", "arity", "means", "ex")

    def __init__(self, name, arity, means, ex):
        self.name, self.arity, self.means, self.ex = name, int(arity), means, ex


def load_predicates(path: str = PREDICATES_YAML) -> dict:
    """name -> Predicate."""
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    out = {}
    for p in data.get("predicates", []):
        out[p["name"]] = Predicate(p["name"], p["arity"], p.get("means", ""), p.get("ex"))
    return out


def predicate_arities_from_operators(operators) -> dict:
    """name -> set(arities) observed across operator pre/post."""
    seen = {}
    for op in operators:
        for pat in list(op.pre) + list(op.post):
            if not pat:
                continue
            seen.setdefault(pat[0], set()).add(len(pat) - 1)
    return seen


def check_coverage(operators) -> list:
    """Return a list of human-readable coverage warnings (empty = clean)."""
    declared = load_predicates()
    used = predicate_arities_from_operators(operators)
    warns = []
    for name, arities in sorted(used.items()):
        if name not in declared:
            warns.append(f"operator predicate '{name}' is not declared in predicates.yaml")
            continue
        if declared[name].arity not in arities:
            warns.append(
                f"'{name}' declared arity {declared[name].arity} but operators use {sorted(arities)}")
    return warns


def vocabulary_block() -> str:
    """A compact, LLM-facing description of every legal predicate."""
    preds = load_predicates()
    lines = []
    for p in preds.values():
        ex = "[" + ", ".join(str(a) for a in (p.ex or [])) + "]" if p.ex else ""
        lines.append(f"  {p.name}/{p.arity}  — {p.means}   e.g. {ex}")
    return "\n".join(lines)


def validate_fact(fact, preds: dict) -> tuple:
    """(ok: bool, reason: str). A fact is a list/tuple: [pred, arg, ...] of scalars."""
    if not isinstance(fact, (list, tuple)) or not fact:
        return False, "not a non-empty list"
    name = fact[0]
    arity = len(fact) - 1
    if name not in preds:
        return False, f"unknown predicate '{name}'"
    if preds[name].arity != arity:
        return False, f"'{name}' expects arity {preds[name].arity}, got {arity}"
    for a in fact[1:]:
        if not isinstance(a, (str, int, float)):
            return False, f"argument {a!r} is not a scalar"
    return True, ""


def validate_pattern(pat, preds: dict) -> tuple:
    """Like validate_fact but for operator pre/post PATTERNS, whose args may be
    variables (strings starting with '?'). Only the predicate name + arity are
    schema-checked; args must be scalars or variables."""
    if not isinstance(pat, (list, tuple)) or not pat:
        return False, "not a non-empty list"
    name = pat[0]
    arity = len(pat) - 1
    if name not in preds:
        return False, f"unknown predicate '{name}'"
    if preds[name].arity != arity:
        return False, f"'{name}' expects arity {preds[name].arity}, got {arity}"
    for a in pat[1:]:
        if not isinstance(a, (str, int, float)):
            return False, f"argument {a!r} is not a scalar/variable"
    return True, ""
