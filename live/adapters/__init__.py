#!/usr/bin/env python3
"""adapters — one typed normalizer per tool. Every adapter returns ObservationRecords
(plus appmodel folds for discovery tools). Adapters are deterministic parsers and
policy gates: they never invoke the target, never hold LLM opinions, and never emit
confirmed findings — confirmation belongs to the Laboratory + skeptic only.
"""
from . import burp, interactsh, katana, mitmproxy, nuclei, playwright, restler, schemathesis, zap

ADAPTERS = {
    "nuclei": nuclei,
    "katana": katana,
    "mitmproxy": mitmproxy,
    "playwright": playwright,
    "zap": zap,
    "restler": restler,
    "schemathesis": schemathesis,
    "interactsh": interactsh,
    "burp": burp,
}


def adapt(tool, raw, ctx=None):
    """tool -> adapter.adapt(raw, ctx) -> {"records": [...], "folds": [...]}"""
    if tool not in ADAPTERS:
        raise KeyError(f"no adapter for tool {tool!r}; available: {sorted(ADAPTERS)}")
    out = ADAPTERS[tool].adapt(raw, ctx or {})
    if isinstance(out, dict):
        return {"records": out.get("records", []), "folds": out.get("folds", [])}
    return {"records": list(out or []), "folds": []}


__all__ = ["ADAPTERS", "adapt"]
