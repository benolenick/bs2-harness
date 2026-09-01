"""Load the operator corpus and target fact-graphs from YAML."""
from __future__ import annotations
import os
import yaml
from .model import Operator, Target

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.join(_HERE, "corpus", "operators.yaml")
KNOWLEDGE_DIR = os.path.join(_HERE, "corpus", "knowledge")


def _t(x):
    """Recursively convert lists to tuples so patterns are hashable."""
    if isinstance(x, list):
        return tuple(_t(i) for i in x)
    return x


def load_operators(path: str = DEFAULT_CORPUS) -> list:
    with open(path) as f:
        data = yaml.safe_load(f)
    ops = []
    for o in data.get("operators", []):
        ops.append(Operator(
            name=o["name"],
            pre=[_t(p) for p in o.get("pre", [])],
            post=[_t(p) for p in o.get("post", [])],
            desc=o.get("desc", ""),
            cost=float(o.get("cost", 1.0)),
            tags=o.get("tags", []),
            refs=o.get("refs", []),
        ))
    return ops


def load_knowledge(directory: str = KNOWLEDGE_DIR) -> set:
    """Load universal knowledge facts (e.g. the GTFOBins table) that apply to
    every target. Each YAML in the knowledge dir contributes a `facts:` list."""
    import glob
    facts = set()
    if not os.path.isdir(directory):
        return facts
    for path in sorted(glob.glob(os.path.join(directory, "*.yaml"))):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for fact in data.get("facts", []):
            facts.add(_t(fact))
    return facts


def load_target(path: str) -> Target:
    with open(path) as f:
        data = yaml.safe_load(f)
    return Target(
        name=data["name"],
        facts=set(_t(f) for f in data.get("facts", [])),
        negatives=set(_t(n) for n in data.get("negatives", [])),
        goal=_t(data["goal"]),
        notes=data.get("notes", ""),
    )
