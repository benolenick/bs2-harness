"""Public package surface for Cartographer."""

from . import environment
from .core import Cartographer, main
from .model import (
    DEAD,
    ENUMERATING,
    EXHAUSTED,
    FOOTHOLD,
    LEDGER,
    OFF_FRONTIER,
    PAYOFF,
    RITUAL_GUIDE,
    RITUALS,
    STATE_MULT,
    UNTOUCHED,
    guide_for,
)

# Preserve the original single-module identities for repr/pickle compatibility.
Cartographer.__module__ = __name__
main.__module__ = __name__

__all__ = [
    "Cartographer",
    "LEDGER",
    "UNTOUCHED",
    "ENUMERATING",
    "EXHAUSTED",
    "FOOTHOLD",
    "DEAD",
    "OFF_FRONTIER",
    "RITUALS",
    "RITUAL_GUIDE",
    "guide_for",
    "PAYOFF",
    "STATE_MULT",
    "environment",
    "main",
]
