"""Ariadne: thread the path through a system.

Given a fact-graph of a target and a corpus of technique-operators, find ranked
attack paths from what you have to what you want, by goal-directed backward
chaining. Fewest unverified assumptions wins; confirmed-negatives prune dead
branches automatically.
"""
from .model import Operator, Target, unify, substitute
from .planner import Planner, Solution
from .loader import load_operators, load_target

__all__ = ["Operator", "Target", "Planner", "Solution",
           "load_operators", "load_target", "unify", "substitute"]
__version__ = "0.1.0"
