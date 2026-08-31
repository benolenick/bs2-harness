#!/usr/bin/env python3
"""Trusted ingestion-side projector installed as root-owned ``lenzd``."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCHEMA = "lenz/v3"
ENVELOPE_SCHEMA = "lenz/signed-v2"
RAW_ROOT = Path(os.environ.get("LENZ_RAW_ROOT", "/tmp/claude-1000/-home-om"))
SAFE_ROOT = Path(os.environ.get("LENZ_SAFE_ROOT", "/opt/bs2/run/lenz"))
PRIVATE_KEY = Path(os.environ.get("LENZ_PRIVATE_KEY", "/etc/lenz/private.pem"))
ACTIVE_NAME_RE = re.compile(r"htb-[A-Za-z0-9._-]{1,180}")
KNOWN_EVENTS = {
    "boot", "coverage", "environment", "manager", "ran", "stop", "done",
    "done_forced", "done_refused", "finding", "hypothesis_raised", "verdict",
    "final", "report",
    "translation",
}
VERBS = {"RUN", "FINDING", "VERDICT", "HYPOTHESIS", "DONE", "INVALID"}
VERDICTS = {"confirmed", "rejected", "inconclusive"}
TRANSLATION_CHANNELS = {"feed", "manager", "hands", "system"}
TRANSLATION_CODES = {"feed_update", "manager_action", "hands_result", "coverage_update", "run_finished"}
TRANSLATION_STATUSES = {
    "memory_available", "memory_unavailable", "run", "finding", "hypothesis", "verdict",
    "done", "invalid", "completed", "blocked", "success", "no_signal", "ongoing",
    "complete", "stopped", "forced", "refused", "error",
}


def _render_translation(code: str, count: int, count2: int, status: str) -> str:
    if code == "feed_update" and status in {"memory_available", "memory_unavailable"}:
        return f"Manager received {count} mapped items and {count2} routes; memory was {status.removeprefix('memory_')}."
    if code == "manager_action" and status in {"run", "finding", "hypothesis", "verdict", "done", "invalid"}:
        return f"Manager selected a {status} action with {count} routes visible."
    if code == "hands_result" and status in {"completed", "blocked", "success", "no_signal"}:
        return f"Hands completed {count} commands; result was {status.replace('_', ' ')}."
    if code == "coverage_update" and status in {"ongoing", "complete"}:
        return f"Coverage was {count} percent with {count2} untouched surfaces; state was {status}."
    if code == "run_finished" and status in {"complete", "stopped", "forced", "refused", "error"}:
        return f"Run state was {status}; {count} lanes dispatched and {count2} solved."
    raise ProjectionFailure("invalid_event")


class ProjectionFailure(RuntimeError):
    def __init__(self, code: str, malformed: int = 0, unknown: int = 0):
        super().__init__(code)
        self.code, self.malformed, self.unknown = code, malformed, unknown


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _integer(row: dict[str, Any], key: str, maximum: int, required: bool = False) -> int:
    value = row.get(key)
    if value is None and not required:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProjectionFailure("invalid_event")
    return value


def _number(row: dict[str, Any], key: str, maximum: float, required: bool = False) -> float:
    value = row.get(key)
    if value is None and not required:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ProjectionFailure("invalid_event")
    value = float(value)
    if not 0 <= value <= maximum:
        raise ProjectionFailure("invalid_event")
    return round(value, 1)


def _boolean(row: dict[str, Any], key: str, required: bool = False) -> bool:
    value = row.get(key)
    if value is None and not required:
        return False
    if type(value) is not bool:
        raise ProjectionFailure("invalid_event")
    return value


def _read_pointer(raw_root: Path) -> Path:
    try:
        fd = os.open(raw_root / "active-run.ref", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            value = os.read(fd, 512).decode("ascii", errors="strict").strip()
        finally:
            os.close(fd)
    except (OSError, UnicodeError):
        raise ProjectionFailure("no_active_run") from None
    if not ACTIVE_NAME_RE.fullmatch(value):
        raise ProjectionFailure("active_pointer_invalid")
    candidate = raw_root / value
    try:
        if candidate.is_symlink() or candidate.resolve().parent != raw_root.resolve():
            raise ProjectionFailure("active_pointer_invalid")
    except OSError:
        raise ProjectionFailure("source_unavailable") from None
    return candidate


def _read_events(path: Path, now: float) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise ProjectionFailure("source_unavailable")
    try:
        text = path.read_bytes().decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        raise ProjectionFailure("source_unavailable") from None
    if not text or not text.endswith("\n"):
        raise ProjectionFailure("malformed_input", malformed=1)
    rows, malformed, unknown = [], 0, 0
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            malformed += 1
            continue
        if not isinstance(row, dict) or not isinstance(row.get("event"), str):
            malformed += 1
        elif row["event"] not in KNOWN_EVENTS:
            unknown += 1
        else:
            rows.append(row)
    if malformed:
        raise ProjectionFailure("malformed_input", malformed, unknown)
    if unknown:
        raise ProjectionFailure("unknown_event", unknown=unknown)
    if not rows:
        raise ProjectionFailure("malformed_input", malformed=1)
    previous_seq, previous_ts, previous_elapsed, boots = 0, 0.0, 0.0, 0
    for index, row in enumerate(rows):
        seq = _integer(row, "seq", 10**9, True)
        ts = _number(row, "ts_epoch", 10**11, True)
        elapsed = _number(row, "elapsed_s", 10**9, True)
        if seq != previous_seq + 1 or ts < previous_ts or elapsed < previous_elapsed:
            raise ProjectionFailure("sequence_invalid")
        if ts > now + 30:
            raise ProjectionFailure("clock_invalid")
        if row["event"] == "boot":
            boots += 1
            if index != 0:
                raise ProjectionFailure("sequence_invalid")
        previous_seq, previous_ts, previous_elapsed = seq, ts, elapsed
    if boots != 1:
        raise ProjectionFailure("sequence_invalid")
    return rows


def _run_ref(source_dir: Path, key: Ed25519PrivateKey) -> str:
    digest = hmac.new(key.private_bytes_raw(), os.fsencode(str(source_dir.resolve())), hashlib.sha256).hexdigest()[:16]
    return f"lenz-{digest}"


def _empty(now: float, reason: str, malformed: int = 0, unknown: int = 0) -> dict[str, Any]:
    warning_for = {"malformed_input": "malformed_input", "unknown_event": "unknown_schema",
                   "invalid_event": "invalid_event", "sequence_invalid": "sequence_invalid",
                   "clock_invalid": "clock_invalid"}
    warnings = [warning_for[reason]] if reason in warning_for else []
    return {
        "schema": SCHEMA, "run_ref": "lenz-0000000000000000", "projected_epoch": round(now, 3),
        "source_last_epoch": 0.0,
        "observer": {"state": "blocked", "reason_code": reason, "records_accepted": 0,
                     "records_rejected": malformed + unknown, "unknown_event_count": unknown},
        "lifecycle": {"state": "observer_blocked", "step": 0, "budget": 0,
                      "budget_used_pct": 0.0, "elapsed_seconds": 0.0,
                      "source_update_age_seconds": 0.0, "terminal_kind": "none", "report_emitted": False},
        "progress": {"coverage_pct": 0.0, "coverage_complete": False, "untouched_surfaces": 0,
                     "open_hypotheses": 0, "route_options": 0, "memory_feed_available": False},
        "execution": {"attempts": 0, "commands_fired": 0, "blocked_attempts": 0,
                      "consecutive_blocked": 0, "mean_duration_seconds": 0.0, "last_duration_seconds": 0.0},
        "environment": {"hosts": 0, "sessions": 0, "credential_artifacts": 0},
        "assessment": {"hypotheses_raised": 0, "verdicts": {k: 0 for k in sorted(VERDICTS)},
                       "findings": 0, "evidence_bound_findings": 0,
                       "manager_verbs": {k: 0 for k in sorted(VERBS)}},
        "translations": [],
        "warnings": warnings,
    }


def project(path: Path, key: Ed25519PrivateKey, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    rows = _read_events(path, now)
    budget = step = attempts = blocked_attempts = consecutive_blocked = commands = routes = 0
    coverage_pct = elapsed = last_ts = 0.0
    coverage_complete = memoria = report_seen = False
    open_hypotheses = untouched = hosts = sessions = credentials = 0
    hypotheses_raised = findings = evidence_bound = 0
    durations: list[float] = []
    verdicts = {k: 0 for k in sorted(VERDICTS)}
    manager_verbs = {k: 0 for k in sorted(VERBS)}
    done_kind = "none"
    translations: list[dict[str, Any]] = []
    for row in rows:
        event = row["event"]
        last_ts, elapsed = _number(row, "ts_epoch", 10**11, True), _number(row, "elapsed_s", 10**9, True)
        if "step" in row:
            step = max(step, _integer(row, "step", 100000))
        if event == "boot":
            budget = _integer(row, "steps", 100000, True)
        elif event == "coverage":
            coverage_pct = _number(row, "pct", 100, True)
            open_hypotheses = _integer(row, "open_count", 100000, True)
            untouched = _integer(row, "untouched_count", 100000, True)
            coverage_complete = _boolean(row, "complete", True)
        elif event == "environment":
            hosts = _integer(row, "host_count", 100000, True)
            sessions = _integer(row, "session_count", 100000, True)
            credentials = _integer(row, "cred_count", 100000, True)
        elif event == "manager":
            verb = row.get("verb")
            if verb not in VERBS:
                raise ProjectionFailure("invalid_event")
            manager_verbs[verb] += 1
            routes = _integer(row, "routes", 100000, True)
            memoria = _boolean(row, "memoria", True)
        elif event == "ran":
            attempts += 1
            commands += _integer(row, "cmds", 1000, True)
            durations.append(_number(row, "secs", 86400, True))
            if _boolean(row, "blocked", True):
                blocked_attempts += 1
                consecutive_blocked += 1
            else:
                consecutive_blocked = 0
        elif event == "hypothesis_raised":
            hypotheses_raised += 1
        elif event == "verdict":
            verdict = row.get("verdict")
            if verdict not in VERDICTS:
                raise ProjectionFailure("invalid_event")
            verdicts[verdict] += 1
        elif event == "finding":
            findings += 1
            refs = row.get("evidence_refs", [])
            if not isinstance(refs, list):
                raise ProjectionFailure("invalid_event")
            evidence_bound += bool(refs)
        elif event == "translation":
            channel, code, status = row.get("channel"), row.get("code"), row.get("status")
            if channel not in TRANSLATION_CHANNELS or code not in TRANSLATION_CODES or status not in TRANSLATION_STATUSES:
                raise ProjectionFailure("invalid_event")
            count = _integer(row, "count", 100000, True)
            count2 = _integer(row, "count2", 100000, True)
            translations.append({"step": _integer(row, "step", 100000, True),
                                 "channel": channel,
                                 "text": _render_translation(code, count, count2, status)})
        elif event == "done": done_kind = "complete"
        elif event == "done_forced": done_kind = "forced"
        elif event == "done_refused": done_kind = "refused"
        elif event == "stop": done_kind = "stopped"
        elif event == "report": report_seen = True
    source_age = round(max(0.0, now - last_ts), 1)
    terminal = done_kind in {"complete", "forced", "stopped"} or report_seen
    lifecycle = (("complete" if done_kind == "complete" and coverage_complete else "terminated")
                 if terminal else ("stale" if source_age > 300 else "running"))
    warnings = []
    if coverage_complete and attempts == 0: warnings.append("premature_completion_signal")
    if attempts >= 3 and hypotheses_raised == 0: warnings.append("no_hypothesis_lifecycle")
    if consecutive_blocked >= 3: warnings.append("repeated_blocking")
    if lifecycle == "stale": warnings.append("no_recent_progress")
    return {
        "schema": SCHEMA, "run_ref": _run_ref(path.parent, key), "projected_epoch": round(now, 3),
        "source_last_epoch": last_ts,
        "observer": {"state": "ready", "reason_code": "none", "records_accepted": len(rows),
                     "records_rejected": 0, "unknown_event_count": 0},
        "lifecycle": {"state": lifecycle, "step": step, "budget": budget,
                      "budget_used_pct": round(100.0 * step / budget, 1) if budget else 0.0,
                      "elapsed_seconds": elapsed, "source_update_age_seconds": source_age,
                      "terminal_kind": done_kind, "report_emitted": report_seen},
        "progress": {"coverage_pct": coverage_pct, "coverage_complete": coverage_complete,
                     "untouched_surfaces": untouched, "open_hypotheses": open_hypotheses,
                     "route_options": routes, "memory_feed_available": memoria},
        "execution": {"attempts": attempts, "commands_fired": commands,
                      "blocked_attempts": blocked_attempts, "consecutive_blocked": consecutive_blocked,
                      "mean_duration_seconds": round(sum(durations) / len(durations), 1) if durations else 0.0,
                      "last_duration_seconds": durations[-1] if durations else 0.0},
        "environment": {"hosts": hosts, "sessions": sessions, "credential_artifacts": credentials},
        "assessment": {"hypotheses_raised": hypotheses_raised, "verdicts": verdicts,
                       "findings": findings, "evidence_bound_findings": evidence_bound,
                       "manager_verbs": manager_verbs}, "warnings": sorted(set(warnings)),
        "translations": translations[-40:],
    }


def load_private_key(path: Path = PRIVATE_KEY) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        raise ProjectionFailure("projection_error") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ProjectionFailure("projection_error")
    return key


def sign(payload: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"schema": ENVELOPE_SCHEMA,
            "key_id": "lenz-ed25519-" + hashlib.sha256(public).hexdigest()[:16],
            "payload": payload,
            "signature": base64.b64encode(key.sign(_canonical(payload))).decode("ascii")}


def _write(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    try:
        os.write(fd, _canonical(obj) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def project_active(raw_root: Path = RAW_ROOT, safe_root: Path = SAFE_ROOT,
                   key_path: Path = PRIVATE_KEY, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    key = load_private_key(key_path)
    try:
        payload = project(_read_pointer(raw_root) / "telemetry.jsonl", key, now)
    except ProjectionFailure as exc:
        payload = _empty(now, exc.code, exc.malformed, exc.unknown)
    envelope = sign(payload, key)
    _write(safe_root / "latest.json", envelope)
    if payload["run_ref"] != "lenz-0000000000000000":
        _write(safe_root / "runs" / f"{payload['run_ref']}.json", envelope)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lenzd")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    while True:
        project_active()
        if args.once:
            return 0
        time.sleep(max(0.5, min(60.0, args.interval)))


if __name__ == "__main__":
    raise SystemExit(main())
