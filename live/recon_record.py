#!/usr/bin/env python3
"""Typed, content-blind observation contract for the BS2 discovery layer."""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field

KINDS = ("port", "service", "vhost", "endpoint", "enum", "verified", "negative")
REQUIRED = ("target", "node_id", "kind", "producer")


@dataclass
class ReconObservation:
    target: str
    ts: int
    node_id: str
    kind: str
    data: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    producer: str = "hands"

    def validate(self):
        problems = []
        for name in REQUIRED:
            if not getattr(self, name):
                problems.append(f"missing required field: {name}")
        if self.kind not in KINDS:
            problems.append(f"kind must be one of {KINDS}, got {self.kind!r}")
        if not isinstance(self.ts, int) or self.ts < 0:
            problems.append("ts must be a non-negative integer")
        if not isinstance(self.data, dict):
            problems.append("data must be a dict")
        if not isinstance(self.evidence, list) or not all(
                isinstance(item, str) and item for item in self.evidence):
            problems.append("evidence must be a list of non-empty refs")
        fold = self.data.get("fold") if isinstance(self.data, dict) else None
        if fold is not None and (not isinstance(fold, str) or not fold.strip()):
            problems.append("data.fold must be a non-empty string when present")
        return problems

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, value):
        fields = {f.name for f in dataclasses.fields(cls)}
        required = {f.name for f in dataclasses.fields(cls)
                    if f.default is dataclasses.MISSING
                    and f.default_factory is dataclasses.MISSING}
        values = {name: None for name in required}
        values.update({k: v for k, v in (value or {}).items() if k in fields})
        return cls(**values)

    def to_json(self):
        return json.dumps(self.to_dict(), indent=1, default=str)

    def to_fold(self):
        """Return the legacy fold representation carried by this typed record."""
        return self.data.get("fold", "") if isinstance(self.data, dict) else ""


__all__ = ["ReconObservation", "KINDS", "REQUIRED"]
