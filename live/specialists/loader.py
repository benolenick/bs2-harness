#!/usr/bin/env python3
"""loader — validate and load the typed specialist contracts (YAML, BS2 doc §4)."""
from __future__ import annotations
import os
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None

SPECIALIST_DIR = Path(__file__).resolve().parent

REQUIRED_KEYS = {
    "id", "triggers", "requires", "allowed_adapters", "max_requests", "max_tokens",
    "max_minutes", "mutation_policy", "success_oracle", "terminal_states",
    "wake_again_on",
}
ALLOWED_ADAPTERS = {"differential-replay", "workflow-map", "session-vault"}
ALLOWED_MUTATION = {"read_only", "write_approved"}
TERMINAL_STATES = {"confirmed", "rejected", "inconclusive", "blocked", "not_applicable"}
ORACLES = {"foreign_object_returned", "foreign_object_modified", "hidden_prop_effected",
           "session_acceptance_mismatch", "state_skipped", "stale_token_accepted",
           "self_approval_succeeded", "replay_accepted"}


def validate(spec):
    """A contract must be complete and closed — a malformed specialist fails LOUD."""
    problems = []
    missing = REQUIRED_KEYS - set(spec or {})
    if missing:
        problems.append(f"missing keys: {sorted(missing)}")
    for a in spec.get("allowed_adapters", []):
        if a not in ALLOWED_ADAPTERS:
            problems.append(f"unknown adapter {a!r}")
    if spec.get("mutation_policy") not in ALLOWED_MUTATION:
        problems.append(f"bad mutation_policy {spec.get('mutation_policy')!r}")
    bad_oracle = set(spec.get("success_oracle", [])) - ORACLES
    if bad_oracle:
        problems.append(f"unknown oracles {sorted(bad_oracle)}")
    bad_term = set(spec.get("terminal_states", [])) - TERMINAL_STATES
    if bad_term:
        problems.append(f"unknown terminal states {sorted(bad_term)}")
    for key in ("max_requests", "max_tokens", "max_minutes"):
        if not isinstance(spec.get(key), int) or spec.get(key, 0) <= 0:
            problems.append(f"{key} must be a positive int")
    if problems:
        raise ValueError(f"specialist {spec.get('id', '?')!r} invalid: {'; '.join(problems)}")
    return spec


def load_specialists(directory=None):
    """Load every *.yaml contract in the specialists dir; raises on the first invalid one."""
    directory = Path(directory or SPECIALIST_DIR)
    if yaml is None:
        raise RuntimeError("PyYAML required to load specialist contracts")
    out = {}
    for path in sorted(directory.glob("*.yaml")):
        spec = yaml.safe_load(path.read_text())
        validate(spec)
        out[spec["id"]] = spec
    return out


__all__ = ["load_specialists", "validate", "SPECIALIST_DIR", "TERMINAL_STATES", "ORACLES"]
