#!/usr/bin/env python3
"""observation — the ONE typed record every BS2 adapter must return (Ben 2026-08-25).

Ben's contract, verbatim intent: every adapter (mitmproxy, Playwright, Katana, ZAP,
Nuclei, Schemathesis, RESTler, Interactsh, Burp-Montoya) returns the same typed record:

  - target and endpoint
  - authenticated principal and tenant
  - originating map node
  - exact control and modified requests
  - normalized response difference
  - tool/version/configuration
  - evidence location
  - confidence and reproducibility
  - whether state was mutated
  - confirmation status

Nothing enters the map as CONFIRMED except through the Laboratory confirm path
(skeptic + evidence refs). Scanners produce hypotheses, never findings — a scanner
record is born kind=hypothesis / confirmation_status=unconfirmed, and validate()
enforces that only kind=finding may ever be confirmed.
"""
from __future__ import annotations
import dataclasses
import json
from dataclasses import dataclass, field

KINDS = ("observation", "hypothesis", "finding")
CONFIRMATION = ("n_a", "unconfirmed", "confirmed", "rejected")
CONFIDENCE = ("low", "medium", "high")

# fields an adapter (or a Burp Montoya extension emitting JSON) must always provide
REQUIRED = ("target", "endpoint", "principal", "map_node", "tool")


@dataclass
class ObservationRecord:
    target: str
    endpoint: dict                      # {id, method, route_template, vhost}
    principal: str                      # "user:user-2" | "anon" | "tenant:t1"
    tenant: str = ""
    map_node: str = "unmapped"          # originating node id (appmodel endpoint id)
    control_request: dict = field(default_factory=dict)
    modified_request: dict = field(default_factory=dict)
    response_delta: dict = field(default_factory=dict)   # the normalized difference
    dom_diff: dict = field(default_factory=dict)         # browser adapters only; {} = not measured
    tool: dict = field(default_factory=dict)             # {name, version, configuration}
    evidence: list = field(default_factory=list)         # file paths / telemetry refs, never bodies
    confidence: str = "low"
    reproducible: bool = False
    state_mutated: bool = False
    kind: str = "hypothesis"
    confirmation_status: str = "unconfirmed"

    def validate(self):
        """Fail-closed structural check. Returns a list of problems ([] = valid).
        Confirmed records must be findings with evidence — scanners can never
        accidentally emit a confirmed record."""
        problems = []
        for k in REQUIRED:
            if not getattr(self, k):
                problems.append(f"missing required field: {k}")
        if self.kind not in KINDS:
            problems.append(f"kind must be one of {KINDS}, got {self.kind!r}")
        if self.confirmation_status not in CONFIRMATION:
            problems.append(f"confirmation_status must be one of {CONFIRMATION}, "
                            f"got {self.confirmation_status!r}")
        if self.confidence not in CONFIDENCE:
            problems.append(f"confidence must be one of {CONFIDENCE}, got {self.confidence!r}")
        if not isinstance(self.endpoint, dict) or not self.endpoint.get("id"):
            problems.append("endpoint must be a dict with an id")
        if not isinstance(self.tool, dict) or not self.tool.get("name"):
            problems.append("tool must be a dict with a name")
        if self.kind in ("hypothesis", "finding") and self.confirmation_status == "n_a":
            problems.append("hypotheses/findings need a confirmation status, not n_a")
        if self.confirmation_status == "confirmed" and not self.evidence:
            problems.append("confirmed requires evidence refs")
        if self.confirmation_status == "confirmed" and self.kind != "finding":
            problems.append("only findings can be confirmed (scanners emit hypotheses)")
        return problems

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d):
        """Tolerant ingestion (Burp wire, disk): missing REQUIRED fields come back as
        None and validate() flags them — invalid records fail closed, never crash."""
        fields = {f.name for f in dataclasses.fields(cls)}
        no_default = {f.name for f in dataclasses.fields(cls)
                      if f.default is dataclasses.MISSING
                      and f.default_factory is dataclasses.MISSING}
        base = {n: None for n in no_default}
        base.update({k: v for k, v in (d or {}).items() if k in fields})
        return cls(**base)

    def to_json(self):
        return json.dumps(self.to_dict(), indent=1, default=str)


__all__ = ["ObservationRecord", "KINDS", "CONFIRMATION", "CONFIDENCE", "REQUIRED"]
