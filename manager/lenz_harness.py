#!/usr/bin/env python3
"""Safe runtime instrumentation shared by BS2 engagement harnesses.

The hands/model may see dirty target output.  This module never does.  Callers give it
only structural counts, booleans, and closed enums distilled from the hands result.  It
writes the exact event vocabulary consumed by the trusted Lenz projector.

Legacy harnesses whose working directory is outside Lenz's raw root use ``mirror()``.
The mirror contains only these safe events; it is not a copy or link to the real run.
"""
from __future__ import annotations

import atexit
import json
import os
import pwd
import re
import subprocess
import time
from pathlib import Path


LENZ_RAW_ROOT = Path("/tmp/claude-1000/-home-om")
RUN_NAME_RE = re.compile(r"htb-[A-Za-z0-9._-]{1,180}")
MANAGER_VERBS = {"RUN", "HYPOTHESIS", "FINDING", "VERDICT", "DONE", "INVALID"}
VERDICTS = {"confirmed", "rejected", "inconclusive"}
TRANSLATION_CHANNELS = {"feed", "manager", "hands", "system"}
TRANSLATION_CODES = {"feed_update", "manager_action", "hands_result", "coverage_update", "run_finished"}
TRANSLATION_STATUSES = {
    "memory_available", "memory_unavailable", "run", "finding", "hypothesis", "verdict",
    "done", "invalid", "completed", "blocked", "success", "no_signal", "ongoing",
    "complete", "stopped", "forced", "refused", "error", "autoturret",
}

_FIELDS = {
    "boot": {"steps"},
    "coverage": {"step", "pct", "open_count", "untouched_count", "complete"},
    "environment": {"step", "host_count", "session_count", "cred_count"},
    "manager": {"step", "verb", "routes", "memoria"},
    "ran": {"step", "secs", "cmds", "blocked"},
    "hypothesis_raised": {"step"},
    "verdict": {"step", "verdict"},
    "finding": {"step", "evidence_refs"},
    "done": {"step"},
    "done_forced": {"step"},
    "done_refused": {"step"},
    "stop": {"step"},
    "final": {"step"},
    "report": {"step"},
    "translation": {"step", "channel", "code", "count", "count2", "status"},
}


def _bounded_int(value, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError("unsafe Lenz integer")
    return value


def _bounded_number(value, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("unsafe Lenz number")
    value = float(value)
    if not 0 <= value <= maximum:
        raise ValueError("unsafe Lenz number")
    return round(value, 1)


def _validate(event, fields):
    if event not in _FIELDS or set(fields) != _FIELDS[event]:
        raise ValueError("unsafe Lenz event shape")
    out = {}
    for key, value in fields.items():
        if key in {"complete", "memoria", "blocked"}:
            if type(value) is not bool:
                raise ValueError("unsafe Lenz boolean")
        elif key == "verb":
            if value not in MANAGER_VERBS:
                raise ValueError("unsafe Lenz manager verb")
        elif key == "verdict":
            if value not in VERDICTS:
                raise ValueError("unsafe Lenz verdict")
        elif key == "evidence_refs":
            if value not in ([], ["bound"]):
                raise ValueError("unsafe Lenz evidence marker")
        elif key == "channel":
            if value not in TRANSLATION_CHANNELS:
                raise ValueError("unsafe Lenz translation channel")
        elif key == "code":
            if value not in TRANSLATION_CODES:
                raise ValueError("unsafe Lenz translation code")
        elif key == "status":
            if value not in TRANSLATION_STATUSES:
                raise ValueError("unsafe Lenz translation status")
        elif key in {"pct", "secs"}:
            value = _bounded_number(value, 86400 if key == "secs" else 100)
        else:
            value = _bounded_int(value, 100000)
        out[key] = value
    return out


def publish_active_run(run_dir, raw_root=LENZ_RAW_ROOT):
    """Atomically make one canonical run visible to the root-owned projector."""
    raw_root = Path(raw_root).resolve()
    run_path = Path(run_dir).resolve()
    if run_path.parent != raw_root or run_path.is_symlink() or not RUN_NAME_RE.fullmatch(run_path.name):
        raise RuntimeError("Lenz rejected run directory")
    try:
        pwd.getpwnam("lenz")
    except KeyError as exc:
        raise RuntimeError("mandatory Lenz account is unavailable") from exc
    # The service must traverse every private parent to reach the pointer.  Granting only the
    # run and pointer is insufficient when /tmp/claude-UID is mode 0700 or has a restrictive
    # ACL mask (the actual production failure behind persistent no_active_run).
    for directory in (raw_root.parent, raw_root):
        subprocess.run(
            ["/usr/bin/setfacl", "-m", "m::--x,u:lenz:--x", str(directory)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    subprocess.run(
        ["/usr/bin/setfacl", "-m", "u:lenz:r-x,d:u:lenz:r-X", str(run_path)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    telemetry = run_path / "telemetry.jsonl"
    if telemetry.exists():
        if telemetry.is_symlink():
            raise RuntimeError("Lenz rejected telemetry symlink")
        subprocess.run(
            ["/usr/bin/setfacl", "-m", "u:lenz:r--", str(telemetry)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    pointer = raw_root / "active-run.ref"
    temporary = raw_root / f".active-run.ref.{os.getpid()}.{time.time_ns()}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (run_path.name + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        subprocess.run(
            ["/usr/bin/setfacl", "-m", "u:lenz:r--", str(temporary)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.replace(temporary, pointer)
        root_fd = os.open(raw_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class SafeLenzStream:
    """Append-only structural event stream; arbitrary text has no API path in."""

    def __init__(self, run_dir, steps):
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "telemetry.jsonl"
        self.started = time.time()
        self.seq = 0
        self.closed = False
        self.terminal_emitted = False
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.emit("boot", steps=_bounded_int(steps, 100000))
        atexit.register(self.stop)

    @classmethod
    def mirror(cls, steps, raw_root=LENZ_RAW_ROOT):
        raw_root = Path(raw_root)
        raw_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = f"htb-observer-{os.getpid()}-{time.time_ns()}"
        stream = cls(raw_root / name, steps)
        publish_active_run(stream.run_dir, raw_root=raw_root)
        return stream

    def emit(self, event, **fields):
        if self.closed:
            raise RuntimeError("Lenz stream is closed")
        clean = _validate(event, fields)
        self.seq += 1
        now = time.time()
        row = {
            "seq": self.seq,
            "event": event,
            "ts_epoch": round(now, 3),
            "elapsed_s": round(now - self.started, 1),
            **clean,
        }
        payload = (json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        if event in {"done", "done_forced", "stop", "report"}:
            self.terminal_emitted = True
        return row

    def observe(self, native_event, **fields):
        """Translate a harness-native event into the closed Lenz schema.

        Harnesses are free to keep rich, evolving telemetry.  Unknown events and arbitrary
        strings stay native-side; they do not break observation and have no route into Lenz.
        """
        step = int(fields.get("step", 0) or 0)
        if native_event == "coverage":
            return self.emit(
                "coverage", step=step, pct=float(fields.get("pct", 0) or 0),
                open_count=int(fields.get("open_count", 0) or 0),
                untouched_count=int(fields.get("untouched_count", 0) or 0),
                complete=bool(fields.get("complete", False)),
            )
        if native_event == "environment":
            return self.emit(
                "environment", step=step,
                host_count=int(fields.get("host_count", 0) or 0),
                session_count=int(fields.get("session_count", 0) or 0),
                cred_count=int(fields.get("cred_count", 0) or 0),
            )
        if native_event == "manager":
            verb = fields.get("verb")
            if verb == "TASK":
                verb = "RUN"
            return self.manager(
                step, verb if verb in MANAGER_VERBS else "INVALID",
                int(fields.get("routes", 0) or 0), bool(fields.get("memoria", False)),
            )
        if native_event == "ran":
            raw_blocked = fields.get("blocked", False)
            blocked = (bool(raw_blocked.strip()) if isinstance(raw_blocked, str)
                       else bool(raw_blocked))
            return self.ran(
                step, float(fields.get("secs", 0) or 0),
                int(fields.get("cmds", 0) or 0), blocked,
            )
        if native_event == "hypothesis_raised":
            return self.emit("hypothesis_raised", step=step)
        if native_event == "verdict" and fields.get("verdict") in VERDICTS:
            return self.emit("verdict", step=step, verdict=fields["verdict"])
        if native_event == "finding":
            return self.finding(step, bool(fields.get("evidence_refs")))
        if native_event in {"done", "done_forced", "done_refused", "stop"}:
            return self.emit(native_event, step=step)
        if native_event == "report":
            return self.emit("report", step=step)
        if native_event == "final":
            return self.emit("final", step=step)
        return None

    def manager(self, step, verb, routes, memoria):
        return self.emit("manager", step=step, verb=verb, routes=routes, memoria=memoria)

    def ran(self, step, secs, cmds, blocked):
        return self.emit("ran", step=step, secs=secs, cmds=cmds, blocked=blocked)

    def finding(self, step, evidence_bound):
        return self.emit("finding", step=step, evidence_refs=["bound"] if evidence_bound else [])

    def translate(self, step, channel, code, count=0, count2=0, status="ongoing"):
        """Publish fixed-template inputs; arbitrary text has no translation path."""
        return self.emit("translation", step=_bounded_int(step, 100000), channel=channel,
                         code=code, count=_bounded_int(count, 100000),
                         count2=_bounded_int(count2, 100000), status=status)

    def stop(self, step=0):
        if not self.closed:
            if not self.terminal_emitted:
                self.emit("stop", step=_bounded_int(step, 100000))
            self.closed = True


class NullLenz:
    """No-op drop-in for SafeLenzStream. The structural mirror exists for the Codex
    consumers (which trip on arbitrary prose); the gunbelt manager loop runs with the
    mirror OFF by default (GB_LENZ=1 re-enables) — Ben 2026-08-25: 'you can turn that
    off, that's only for codex since it trips at everything'."""

    def observe(self, native_event, **fields):
        return None

    def translate(self, step, channel, code, count=0, count2=0, status="ongoing"):
        return None

    def stop(self, step=0):
        return None
