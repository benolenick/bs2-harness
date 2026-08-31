#!/usr/bin/env python3
"""impact — classify a target-touching command's IMPACT and gate it on a risk ceiling.

Codex's critique: blocking rm/dd/mkfs is the wrong abstraction for web pentest; the destructive
ops are DELETE / DROP / account-mutation / mass-extraction. And the LEVEL dial (coverage/spend)
must be ORTHOGONAL to acceptable IMPACT. This is the missing risk axis.

  classify(cmd) -> "read" | "mutate" | "destructive"
  allowed(impact, risk) -> bool          risk in {readonly, safe, full}   (default safe)
"""
import re

_DESTRUCTIVE = re.compile(
    r"(-X\s*DELETE\b|--request\s+DELETE\b|\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\b|"
    r"\bDELETE\s+FROM\b|\bmkfs\b|\bdd\s+if=|\brm\s+-|\bshutdown\b|\breboot\b|\b:>\s*/)", re.I)
_MUTATE = re.compile(
    r"(-X\s*(POST|PUT|PATCH)\b|--request\s+(POST|PUT|PATCH)\b|--data\b|-d\s|\bINSERT\s+INTO\b|"
    r"\bUPDATE\s+\w+\s+SET\b|\bALTER\b|\"role\"\s*:\s*\"admin\")", re.I)

RISK_ALLOWS = {
    "readonly": {"read"},
    "safe":     {"read", "mutate"},
    "full":     {"read", "mutate", "destructive"},
}

def classify(cmd):
    s = cmd if isinstance(cmd, str) else " ".join(cmd)
    if _DESTRUCTIVE.search(s):
        return "destructive"
    if _MUTATE.search(s):
        return "mutate"
    return "read"

def allowed(impact, risk="safe"):
    return impact in RISK_ALLOWS.get(risk or "safe", RISK_ALLOWS["safe"])

if __name__ == "__main__":
    import sys
    c = " ".join(sys.argv[1:])
    imp = classify(c)
    print(f"impact={imp}  readonly={allowed(imp,'readonly')} safe={allowed(imp,'safe')} full={allowed(imp,'full')}")
