"""Ariadne core model: facts, patterns, operators, and unification.

A FACT is a ground tuple of strings, e.g. ("runs_as", "sysmind", "webappuser").
A PATTERN is a tuple that may contain variables (strings beginning with "?"),
e.g. ("can_read", "?u", "?file"). Unification binds variables so a pattern
matches a fact or another pattern.

An OPERATOR is a technique: a set of precondition patterns that, if satisfied,
yield a set of postcondition patterns. Operators are the reusable "edges" that
connect what an attacker has to what they want.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


def is_var(x) -> bool:
    return isinstance(x, str) and x.startswith("?")


def walk(x, subst: dict):
    """Follow the binding chain for a variable."""
    while is_var(x) and x in subst:
        x = subst[x]
    return x


def unify(a, b, subst: Optional[dict] = None):
    """Unify two tuples (or terms). Returns an extended substitution dict, or None.

    subst is treated as immutable by the caller: we copy before extending.
    """
    if subst is None:
        subst = {}
    # term-level
    if isinstance(a, tuple) and isinstance(b, tuple):
        if len(a) != len(b):
            return None
        s = dict(subst)
        for ai, bi in zip(a, b):
            s = unify(ai, bi, s)
            if s is None:
                return None
        return s
    a = walk(a, subst)
    b = walk(b, subst)
    if a == b:
        return subst
    if is_var(a):
        s = dict(subst)
        s[a] = b
        return s
    if is_var(b):
        s = dict(subst)
        s[b] = a
        return s
    return None


def substitute(pattern: tuple, subst: dict) -> tuple:
    """Apply a substitution to a pattern, grounding bound variables."""
    return tuple(walk(x, subst) for x in pattern)


def rename_pattern(pattern: tuple, n) -> tuple:
    """Standardize apart: give every variable in a pattern a fresh, unique name
    so that reusing an operator (or nesting operators that share variable names
    like ?role/?u) cannot cause spurious binding collisions."""
    return tuple((f"{x}#{n}" if is_var(x) else x) for x in pattern)


def is_ground(pattern: tuple) -> bool:
    return not any(is_var(walk(x, {})) for x in pattern)


@dataclass
class Operator:
    """A technique: preconditions -> postconditions.

    cost:      relative effort/noise of the technique (lower = prefer).
    tags:      free-form labels (web, os, ai, privesc, ...).
    refs:      external references (CWE, OWASP, ATLAS, notes).
    """
    name: str
    pre: list = field(default_factory=list)      # list[tuple]
    post: list = field(default_factory=list)     # list[tuple]
    desc: str = ""
    cost: float = 1.0
    tags: list = field(default_factory=list)
    refs: list = field(default_factory=list)

    def __post_init__(self):
        self.pre = [tuple(p) for p in self.pre]
        self.post = [tuple(p) for p in self.post]


@dataclass
class Target:
    """A concrete system under assessment."""
    name: str
    facts: set = field(default_factory=set)       # set[tuple] : confirmed true
    negatives: set = field(default_factory=set)   # set[tuple] : confirmed FALSE (hard prune)
    goal: tuple = None                            # pattern to achieve
    notes: str = ""

    def __post_init__(self):
        self.facts = set(tuple(f) for f in self.facts)
        self.negatives = set(tuple(n) for n in self.negatives)
        if self.goal is not None:
            self.goal = tuple(self.goal)
