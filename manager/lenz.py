#!/usr/bin/env python3
"""Read-only Lenz consumer for signed structural BS2 projections."""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA = "lenz/v3"
LEGACY_SCHEMA = "lenz/v2"
ENVELOPE_SCHEMA = "lenz/signed-v2"
VERIFY_SCHEMA = "lenz/verification-v2"
SAFE_ROOT = Path(os.environ.get("LENZ_SAFE_ROOT", "/opt/bs2/run/lenz"))
PUBLIC_KEY = Path(os.environ.get("LENZ_PUBLIC_KEY", "/etc/lenz/public.pem"))
MAX_PROJECTION_AGE = float(os.environ.get("LENZ_MAX_PROJECTION_AGE", "15"))
MAX_FUTURE_SKEW = 5.0
RUN_REF_RE = re.compile(r"lenz-[0-9a-f]{16}")
KEY_ID_RE = re.compile(r"lenz-ed25519-[0-9a-f]{16}")

OBSERVER_STATES = {"ready", "blocked"}
REASON_CODES = {
    "none", "no_active_run", "active_pointer_invalid", "source_unavailable",
    "malformed_input", "unknown_event", "invalid_event", "sequence_invalid",
    "clock_invalid", "projection_error",
}
LIFECYCLE_STATES = {"observer_blocked", "running", "stale", "complete", "terminated"}
TERMINAL_KINDS = {"none", "complete", "forced", "refused", "stopped"}
WARNINGS = {
    "premature_completion_signal", "no_hypothesis_lifecycle", "repeated_blocking",
    "no_recent_progress", "malformed_input", "unknown_schema", "invalid_event",
    "sequence_invalid", "clock_invalid",
}
VERBS = {"RUN", "FINDING", "VERDICT", "HYPOTHESIS", "DONE", "INVALID"}
VERDICTS = {"confirmed", "rejected", "inconclusive"}
TRANSLATION_CHANNELS = {"feed", "manager", "hands", "system"}
TRANSLATION_TEXT_RE = re.compile(
    r"(?:Manager received \d+ mapped items and \d+ routes; memory was (?:available|unavailable)\."
    r"|Manager selected a (?:run|finding|hypothesis|verdict|done|invalid) action with \d+ routes visible\."
    r"|Hands completed \d+ commands; result was (?:completed|blocked|success|no signal)\."
    r"|Coverage was \d+ percent with \d+ untouched surfaces; state was (?:ongoing|complete)\."
    r"|Run state was (?:complete|stopped|forced|refused|error); \d+ lanes dispatched and \d+ solved\.)"
)


class LenzError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _dict(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LenzError("schema_invalid")
    return value


def _int(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise LenzError("schema_invalid")
    return value


def _num(value: Any, minimum: float, maximum: float) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LenzError("schema_invalid")
    if not math.isfinite(float(value)) or not minimum <= float(value) <= maximum:
        raise LenzError("schema_invalid")
    return value


def _bool(value: Any) -> bool:
    if type(value) is not bool:
        raise LenzError("schema_invalid")
    return value


def _enum(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise LenzError("schema_invalid")
    return value


def validate_projection(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise LenzError("schema_invalid")
    schema = obj.get("schema")
    common_keys = {
        "schema", "run_ref", "projected_epoch", "source_last_epoch", "observer",
        "lifecycle", "progress", "execution", "environment", "assessment", "warnings",
    }
    if schema == SCHEMA:
        top = _dict(obj, common_keys | {"translations"})
    elif schema == LEGACY_SCHEMA:
        top = _dict(obj, common_keys)
    else:
        raise LenzError("schema_invalid")
    if not isinstance(top["run_ref"], str) or not RUN_REF_RE.fullmatch(top["run_ref"]):
        raise LenzError("schema_invalid")
    _num(top["projected_epoch"], 0, 10**11)
    _num(top["source_last_epoch"], 0, 10**11)

    observer = _dict(top["observer"], {
        "state", "reason_code", "records_accepted", "records_rejected", "unknown_event_count",
    })
    _enum(observer["state"], OBSERVER_STATES)
    _enum(observer["reason_code"], REASON_CODES)
    for key in ("records_accepted", "records_rejected", "unknown_event_count"):
        _int(observer[key], 0, 10**9)
    if (observer["state"] == "ready") != (observer["reason_code"] == "none"):
        raise LenzError("schema_invalid")

    lifecycle = _dict(top["lifecycle"], {
        "state", "step", "budget", "budget_used_pct", "elapsed_seconds",
        "source_update_age_seconds", "terminal_kind", "report_emitted",
    })
    _enum(lifecycle["state"], LIFECYCLE_STATES)
    _int(lifecycle["step"], 0, 100000)
    _int(lifecycle["budget"], 0, 100000)
    _num(lifecycle["budget_used_pct"], 0, 100000)
    _num(lifecycle["elapsed_seconds"], 0, 10**9)
    _num(lifecycle["source_update_age_seconds"], 0, 10**9)
    _enum(lifecycle["terminal_kind"], TERMINAL_KINDS)
    _bool(lifecycle["report_emitted"])

    progress = _dict(top["progress"], {
        "coverage_pct", "coverage_complete", "untouched_surfaces", "open_hypotheses",
        "route_options", "memory_feed_available",
    })
    _num(progress["coverage_pct"], 0, 100)
    _bool(progress["coverage_complete"])
    for key in ("untouched_surfaces", "open_hypotheses", "route_options"):
        _int(progress[key], 0, 100000)
    _bool(progress["memory_feed_available"])

    execution = _dict(top["execution"], {
        "attempts", "commands_fired", "blocked_attempts", "consecutive_blocked",
        "mean_duration_seconds", "last_duration_seconds",
    })
    for key in ("attempts", "commands_fired", "blocked_attempts", "consecutive_blocked"):
        _int(execution[key], 0, 10**9)
    _num(execution["mean_duration_seconds"], 0, 86400)
    _num(execution["last_duration_seconds"], 0, 86400)

    environment = _dict(top["environment"], {"hosts", "sessions", "credential_artifacts"})
    for value in environment.values():
        _int(value, 0, 100000)

    assessment = _dict(top["assessment"], {
        "hypotheses_raised", "verdicts", "findings", "evidence_bound_findings", "manager_verbs",
    })
    _int(assessment["hypotheses_raised"], 0, 10**9)
    _int(assessment["findings"], 0, 10**9)
    _int(assessment["evidence_bound_findings"], 0, 10**9)
    verdicts = _dict(assessment["verdicts"], VERDICTS)
    verbs = _dict(assessment["manager_verbs"], VERBS)
    for value in list(verdicts.values()) + list(verbs.values()):
        _int(value, 0, 10**9)

    if not isinstance(top["warnings"], list) or len(top["warnings"]) != len(set(top["warnings"])):
        raise LenzError("schema_invalid")
    for warning in top["warnings"]:
        _enum(warning, WARNINGS)
    if top["warnings"] != sorted(top["warnings"]):
        raise LenzError("schema_invalid")
    if schema == SCHEMA:
        if not isinstance(top["translations"], list) or len(top["translations"]) > 40:
            raise LenzError("schema_invalid")
        for item in top["translations"]:
            item = _dict(item, {"step", "channel", "text"})
            _int(item["step"], 0, 100000)
            _enum(item["channel"], TRANSLATION_CHANNELS)
            if not isinstance(item["text"], str) or not TRANSLATION_TEXT_RE.fullmatch(item["text"]):
                raise LenzError("schema_invalid")
    return top


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError):
        raise LenzError("public_key_unavailable") from None
    if not isinstance(key, Ed25519PublicKey):
        raise LenzError("public_key_invalid")
    return key


def read_signed(path: Path, public_key_path: Path = PUBLIC_KEY) -> dict[str, Any]:
    try:
        envelope = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise LenzError("projection_unavailable") from None
    envelope = _dict(envelope, {"schema", "key_id", "payload", "signature"})
    if envelope["schema"] != ENVELOPE_SCHEMA:
        raise LenzError("envelope_invalid")
    if not isinstance(envelope["key_id"], str) or not KEY_ID_RE.fullmatch(envelope["key_id"]):
        raise LenzError("envelope_invalid")
    if not isinstance(envelope["signature"], str):
        raise LenzError("envelope_invalid")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, TypeError):
        raise LenzError("signature_invalid") from None
    try:
        _load_public_key(public_key_path).verify(signature, _canonical(envelope["payload"]))
    except InvalidSignature:
        raise LenzError("signature_invalid") from None
    return validate_projection(envelope["payload"])


def require_fresh(payload: dict[str, Any], now: float | None = None) -> None:
    now = time.time() if now is None else now
    projected = float(payload["projected_epoch"])
    if projected > now + MAX_FUTURE_SKEW:
        raise LenzError("projection_from_future")
    if now - projected > MAX_PROJECTION_AGE:
        raise LenzError("projection_stale")


def _blocked(code: str) -> dict[str, Any]:
    allowed = {
        "projection_unavailable", "envelope_invalid", "signature_invalid", "schema_invalid",
        "public_key_unavailable", "public_key_invalid", "projection_from_future", "projection_stale",
    }
    return {"schema": VERIFY_SCHEMA, "observer": {"state": "blocked", "reason_code": code if code in allowed else "schema_invalid"}}


def _print(obj: dict[str, Any], compact: bool) -> None:
    print(json.dumps(obj, sort_keys=True, separators=(",", ":") if compact else None, indent=None if compact else 2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lenz", description="Verified read-only BS2 observer")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("latest", "verify"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--compact", action="store_true")
    show = sub.add_parser("show")
    show.add_argument("run_ref")
    show.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "show":
            if not RUN_REF_RE.fullmatch(args.run_ref):
                raise LenzError("schema_invalid")
            payload = read_signed(SAFE_ROOT / "runs" / f"{args.run_ref}.json")
        else:
            payload = read_signed(SAFE_ROOT / "latest.json")
            require_fresh(payload)
        if args.command == "verify":
            state = "ready" if payload["observer"]["state"] == "ready" else "blocked"
            _print({"schema": VERIFY_SCHEMA, "observer": {
                "state": state, "signature": "valid", "freshness": "current",
                "projection_state": payload["observer"]["state"],
            }}, args.compact)
            return 0 if state == "ready" else 2
        _print(payload, args.compact)
        return 0 if payload["observer"]["state"] == "ready" else 2
    except LenzError as exc:
        _print(_blocked(exc.code), True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
