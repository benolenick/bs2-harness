#!/usr/bin/env python3
"""experiment_ledger — the evidence / no-repeat experiment ledger (BS2 doc §5).

The MIT harness wastes usage because agents forget what others already attempted. Every
experiment is fingerprinted by

    endpoint + method + principal + object + mutation + payload family + oracle

and the scheduler asks, before dispatch:

  1. Has an equivalent experiment already run?
  2. Did it fail because the test was NEGATIVE or because execution was BROKEN?
  3. Has any relevant map fact changed since then?
  4. Would this specialist learn anything new?

Negatives are first-class: 'this endpoint correctly rejects cross-tenant access' is
useful knowledge and prevents every other authorization specialist repeating the test.
"""
from __future__ import annotations
import hashlib, json, os
from pathlib import Path


def fingerprint(parts):
    """Deterministic experiment fingerprint: a stable key over the tuple of parts
    (endpoint_id, method, principal, object, mutation, payload_family, oracle)."""
    canon = tuple(str(parts.get(k, "")) for k in
                  ("endpoint_id", "method", "principal", "object", "mutation",
                   "payload_family", "oracle"))
    return hashlib.sha256("\x00".join(canon).encode()).hexdigest()[:24]


class ExperimentLedger:
    def __init__(self, run_dir=None):
        self.run_dir = Path(run_dir) if run_dir else None
        self.records = {}          # fingerprint -> record
        self.map_versions = {}     # fingerprint -> appmodel version at test time

    # ---- the four pre-dispatch questions ---------------------------------------
    def find_equivalent(self, fp):
        """(1) Has an equivalent experiment already run? Returns the prior record or None."""
        return self.records.get(fp)

    def classify_prior(self, fp):
        """(2) Negative vs broken: was the prior run a genuine negative result or an
        execution failure that tells us nothing about the app?"""
        rec = self.records.get(fp)
        if rec is None:
            return "none"
        if rec.get("was_execution_error"):
            return "broken_execution"
        return "genuine_negative" if not rec.get("delta", {}).get("candidate") else "positive"

    def map_changed_since(self, fp, current_version):
        """(3) Has the application model changed since this experiment last ran?
        A changed map invalidates 'no need to retest'."""
        seen = self.map_versions.get(fp)
        return seen is None or current_version is None or int(current_version) > int(seen)

    def should_retest(self, fp, current_version, learns_anything_new):
        """(4) Combined verdict: retest only when execution was broken OR the map moved
        AND the caller can name something new it would learn."""
        prior = self.find_equivalent(fp)
        if prior is None:
            return True, "never_tested"
        if self.classify_prior(fp) == "broken_execution":
            return True, "prior_execution_broken"
        if self.map_changed_since(fp, current_version) and learns_anything_new:
            return True, "map_changed"
        return False, "already_tested"

    # ---- mutation ----------------------------------------------------------------
    def record(self, fp, result):
        self.records[fp] = dict(result or {})
        self.map_versions[fp] = result.get("map_version")

    def stats(self):
        """The operator-facing ledger numbers (§10): duplicates prevented, positives,
        negatives, broken runs."""
        dup = sum(1 for r in self.records.values() if r.get("was_duplicate"))
        pos = sum(1 for r in self.records.values()
                  if r.get("delta", {}).get("candidate") and not r.get("was_execution_error"))
        neg = sum(1 for r in self.records.values()
                  if not r.get("delta", {}).get("candidate") and not r.get("was_execution_error"))
        broken = sum(1 for r in self.records.values() if r.get("was_execution_error"))
        return {"experiments": len(self.records), "duplicates_prevented": dup,
                "positives": pos, "negatives": neg, "broken": broken}

    # ---- persistence -------------------------------------------------------------
    def save(self):
        if not self.run_dir:
            return
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / "experiment_ledger.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"records": self.records,
                                   "map_versions": self.map_versions}, indent=1))
        os.replace(tmp, path)
        try: os.chmod(path, 0o600)
        except Exception: pass

    @classmethod
    def load(cls, run_dir):
        L = cls(run_dir)
        path = Path(run_dir) / "experiment_ledger.json"
        if path.exists():
            d = json.loads(path.read_text())
            L.records = d.get("records", {})
            L.map_versions = d.get("map_versions", {})
        return L

    @classmethod
    def open(cls, run_dir):
        """The shared-lane entry point (2026-08-25): ONE ledger per run dir — loaded if
        a prior lane wrote it, else fresh. Every experiment lane (slice, matrix, lab)
        opens the SAME instance so overlapping experiments dedup across specialists."""
        return cls.load(run_dir)


__all__ = ["ExperimentLedger", "fingerprint"]
