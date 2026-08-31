#!/usr/bin/env python3
"""tools_registry — the P1-3 tool capability registry (re-audit 2026-08-25).

Distinguishes, per tool, what is actually TRUE of it — never a roster entry posing
as a capability:

    catalogued            the tool is known to the Laboratory (has a registry entry)
    installed             a binary/module really exists on the exec host
    version_verified      the binary answered a version probe (installed AND verified)
    adapter_compatible    a typed adapter maps its output -> ObservationRecord
    runner_configured     a governed replay transport exists for its lane
    governed_capable      the open seam holds a capability for its action class
    smoke_tested          a recorded smoke test passed for THIS tool
    enabled               the current charter allows its action class

Honesty rules (the point of the whole exercise):
- nothing is 'installed' or 'verified' by assertion — it is PROBED;
- nothing is 'smoke_tested' until a smoke test actually ran and recorded;
- 'applicable_now' is derived from the charter, never assumed.

usage: python3 tools_registry.py [--seam DIR] [--charter FILE]   # matrix + counts
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    from adapters import ADAPTERS
except Exception:
    ADAPTERS = {}

# tool name -> {adapter (the typed laboratory adapter), binaries (probe candidates),
#               action_class (the governed lane it dispatches through)}
TOOLS = {
    "nuclei":       {"adapter": "nuclei",       "binaries": ["nuclei"],           "cls": "web.recon"},
    "katana":       {"adapter": "katana",       "binaries": ["katana"],           "cls": "web.recon"},
    "mitmproxy":    {"adapter": "mitmproxy",    "binaries": ["mitmdump", "mitmproxy"], "cls": "web.recon"},
    "playwright":   {"adapter": "playwright",   "binaries": [],                   "cls": "web.recon"},
    "zap":          {"adapter": "zap",          "binaries": ["zap.sh", "zaproxy"], "cls": "web.recon"},
    "restler":      {"adapter": "restler",      "binaries": ["Restler", "restler"], "cls": "web.recon"},
    "schemathesis": {"adapter": "schemathesis", "binaries": ["schemathesis"],     "cls": "web.recon"},
    "interactsh":   {"adapter": "interactsh",   "binaries": ["interactsh-client"], "cls": "web.recon"},
    "burp":         {"adapter": "burp",         "binaries": [],                   "cls": "web.recon"},
    "ffuf":         {"adapter": None,           "binaries": ["ffuf"],             "cls": "web.recon"},
    "sqlmap":       {"adapter": None,           "binaries": ["sqlmap"],           "cls": "web.exploit"},
    "httpx":        {"adapter": None,           "binaries": ["httpx"],            "cls": "web.recon"},
}

_VERSION_PROBES = ("-version", "--version", "version")


def _module_available(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


def _probe_version(binary):
    """Run one version probe; returns the version string or None. Never fatal.
    Only a digit-bearing line counts — an error banner ('Unsupported flag: --version')
    is not a version."""
    for flag in _VERSION_PROBES:
        try:
            out = subprocess.run([binary, flag], capture_output=True, text=True,
                                 timeout=8).stdout.strip()
        except Exception:
            continue
        for line in out.splitlines():
            if re.search(r"\d", line):
                return line.strip()[:80]
    return None


class ToolRegistry:
    """One probe-and-derive pass over the tool matrix. All probing is lazy-cached;
    nothing is asserted — every capability is measured or recorded."""

    def __init__(self, which=None, verifier=None, seam_caps=None, charter=None,
                 smoke_file=None, module_available=None):
        self.which = which or shutil.which
        self.verifier = verifier or _probe_version
        self.module_available = module_available or _module_available
        self.seam_caps = set(seam_caps or [])
        self.charter = charter or {}
        self._smoke_file = smoke_file
        self._smoked = set()
        if self._smoke_file and os.path.isfile(self._smoke_file):
            try:
                self._smoked = set(json.load(open(self._smoke_file)))
            except Exception:
                self._smoked = set()
        self._cache = {}

    # ---- probing ---------------------------------------------------------------
    def _installed(self, name):
        spec = TOOLS[name]
        if name == "playwright":                      # python module, not a binary
            return self.module_available("playwright")
        return any(self.which(b) for b in spec["binaries"])

    def _version(self, name):
        spec = TOOLS[name]
        if name == "playwright":                      # module version, not a binary
            try:
                import playwright
                return getattr(playwright, "__version__", "") or None
            except Exception:
                return None
        for b in spec["binaries"]:
            path = self.which(b)
            if not path:
                continue
            v = self.verifier(path)
            if v:
                return v
        return None

    def _allowed(self, name):
        """Charter-gated: the tool's action class must be an allowed action."""
        allowed = set((self.charter.get("actions") or {}).get("allowed") or [])
        return TOOLS[name]["cls"] in allowed

    # ---- the one derived status ------------------------------------------------
    def status(self, name):
        if name not in TOOLS:
            raise KeyError(name)
        if name in self._cache:
            return self._cache[name]
        spec = TOOLS[name]
        installed = self._installed(name)
        version = self._version(name) if installed else None
        st = {
            "catalogued": True,
            "installed": installed,
            "version_verified": bool(version),
            "version": version or "",
            "adapter_compatible": spec["adapter"] in ADAPTERS,
            "runner_configured": spec["adapter"] in ADAPTERS,   # the typed replay path
            "governed_capable": TOOLS[name]["cls"] in self.seam_caps,
            "smoke_tested": name in self._smoked,
            "enabled": self._allowed(name),
            "action_class": spec["cls"],
        }
        self._cache[name] = st
        return st

    def summary(self):
        rows = [self.status(n) for n in TOOLS]
        def count(*fields):
            return sum(1 for r in rows if all(r.get(f) for f in fields))
        return {
            # the re-audit UI vocabulary: separate counts, never one '41 agents' number
            "catalogued": count("catalogued"),
            "routable": count("adapter_compatible"),
            "runnable": count("installed"),
            "verified": count("version_verified"),
            "governed_capable": count("governed_capable"),
            "smoke_tested": count("smoke_tested"),
            "applicable_now": count("enabled"),
        }

    def smoke_passed(self, name):
        """Record one real smoke test result (call only after the test actually ran)."""
        if name not in TOOLS:
            raise KeyError(name)
        self._smoked.add(name)
        self._cache.pop(name, None)
        if self._smoke_file:
            os.makedirs(os.path.dirname(self._smoke_file), exist_ok=True)
            json.dump(sorted(self._smoked), open(self._smoke_file, "w"))
        return self.status(name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seam", default=None, help="open governed seam run-dir")
    ap.add_argument("--charter", default=None, help="charter JSON file")
    ap.add_argument("--smoke-file", default=None)
    a = ap.parse_args()
    caps = set()
    if a.seam:
        try:
            caps = set(json.load(open(f"{a.seam}/seam.json"))["caps"])
        except Exception:
            pass
    charter_doc = {}
    if a.charter and os.path.isfile(a.charter):
        charter_doc = json.load(open(a.charter))
    reg = ToolRegistry(seam_caps=caps, charter=charter_doc, smoke_file=a.smoke_file)
    print(f"{'tool':12} {'installed':9} {'version':8} {'adapter':7} {'governed':8} "
          f"{'smoke':5} {'enabled':7}")
    for name in TOOLS:
        st = reg.status(name)
        print(f"{name:12} {str(st['installed']):9} {st['version'][:8] or '-':8} "
              f"{str(st['adapter_compatible']):7} {str(st['governed_capable']):8} "
              f"{str(st['smoke_tested']):5} {str(st['enabled']):7}")
    s = reg.summary()
    print("\ncounts: " + ", ".join(f"{k}={v}" for k, v in s.items()))


if __name__ == "__main__":
    main()
