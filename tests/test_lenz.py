import copy
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


READER = _load("lenz_reader", ROOT / "manager" / "lenz.py")
PROJECTOR = _load("lenz_projector", ROOT / "manager" / "lenz_projector.py")

POISON = " | ".join([
    "198.51.100.10", "2001:db8::1", "target.invalid", "C:\\Users\\raw",
    "nmap -p- target", "password=hunter2", "eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "flag HTB{never_emit_me}", "dG9rZW49YWJjMTIz",
])


@pytest.fixture
def keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, private_path, public_path


def _write_events(path, rows, trailing_newline=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + ("\n" if trailing_newline else ""))


def _rows(blocked=False):
    return [
        {"seq": 1, "event": "boot", "ts_epoch": 100.0, "elapsed_s": 0.0,
         "target": POISON, "steps": 10, "brain": POISON, "run_dir": POISON},
        {"seq": 2, "event": "coverage", "ts_epoch": 101.0, "elapsed_s": 1.0, "step": 1,
         "pct": 25, "open_count": 2, "untouched_count": 3, "complete": False, "detail": POISON},
        {"seq": 3, "event": "manager", "ts_epoch": 102.0, "elapsed_s": 2.0, "step": 1,
         "verb": "RUN", "routes": 4, "memoria": True, "action": POISON},
        {"seq": 4, "event": "ran", "ts_epoch": 103.0, "elapsed_s": 3.0, "step": 1,
         "secs": 7, "cmds": 1, "blocked": blocked, "command": POISON, "marker": POISON},
    ]


def _signed_fixture(tmp_path, keys, rows=None, now=110.0):
    private, _, public_path = keys
    telemetry = tmp_path / "raw" / "htb-synthetic" / "telemetry.jsonl"
    _write_events(telemetry, rows or _rows())
    payload = PROJECTOR.project(telemetry, private, now)
    envelope = PROJECTOR.sign(payload, private)
    safe = tmp_path / "safe.json"
    safe.write_text(json.dumps(envelope))
    return payload, envelope, safe, public_path


def test_projection_is_structural_and_signed(tmp_path, keys):
    payload, _, safe, public = _signed_fixture(tmp_path, keys)
    assert POISON not in json.dumps(payload)
    assert READER.read_signed(safe, public) == payload
    assert payload["execution"]["attempts"] == 1


def test_reader_rejects_extra_key_even_with_valid_signature(tmp_path, keys):
    private, _, public = keys
    payload, _, safe, _ = _signed_fixture(tmp_path, keys)
    payload["injected"] = "benign-looking.example"
    safe.write_text(json.dumps(PROJECTOR.sign(payload, private)))
    with pytest.raises(READER.LenzError, match="schema_invalid"):
        READER.read_signed(safe, public)


def test_reader_rejects_tampered_payload(tmp_path, keys):
    _, envelope, safe, public = _signed_fixture(tmp_path, keys)
    envelope["payload"]["execution"]["attempts"] = 999
    safe.write_text(json.dumps(envelope))
    with pytest.raises(READER.LenzError, match="signature_invalid"):
        READER.read_signed(safe, public)


def test_reader_rejects_wrong_signer(tmp_path, keys):
    payload, _, safe, public = _signed_fixture(tmp_path, keys)
    safe.write_text(json.dumps(PROJECTOR.sign(payload, Ed25519PrivateKey.generate())))
    with pytest.raises(READER.LenzError, match="signature_invalid"):
        READER.read_signed(safe, public)


def test_reader_rejects_stale_and_future_projection(tmp_path, keys):
    payload, _, _, _ = _signed_fixture(tmp_path, keys)
    with pytest.raises(READER.LenzError, match="projection_stale"):
        READER.require_fresh(payload, now=200)
    future = copy.deepcopy(payload)
    future["projected_epoch"] = 300
    with pytest.raises(READER.LenzError, match="projection_from_future"):
        READER.require_fresh(future, now=200)


@pytest.mark.parametrize("mutator,code", [
    (lambda rows: rows.__setitem__(1, {**rows[1], "seq": 1}), "sequence_invalid"),
    (lambda rows: rows.__setitem__(3, {**rows[3], "blocked": "false"}), "invalid_event"),
    (lambda rows: rows.__setitem__(2, {**rows[2], "verb": "SHELL"}), "invalid_event"),
    (lambda rows: rows.__setitem__(3, {**rows[3], "ts_epoch": 999}), "clock_invalid"),
])
def test_invalid_event_shapes_fail_closed(tmp_path, keys, mutator, code):
    private, _, _ = keys
    rows = _rows()
    mutator(rows)
    telemetry = tmp_path / "raw" / "htb-synthetic" / "telemetry.jsonl"
    _write_events(telemetry, rows)
    with pytest.raises(PROJECTOR.ProjectionFailure, match=code):
        PROJECTOR.project(telemetry, private, now=110)


def test_partial_final_record_fails_closed(tmp_path, keys):
    private, _, _ = keys
    telemetry = tmp_path / "raw" / "htb-synthetic" / "telemetry.jsonl"
    _write_events(telemetry, _rows(), trailing_newline=False)
    with pytest.raises(PROJECTOR.ProjectionFailure, match="malformed_input"):
        PROJECTOR.project(telemetry, private, now=110)


def test_unknown_event_fails_without_echo(tmp_path, keys):
    private, _, _ = keys
    rows = _rows() + [{"seq": 5, "event": "LEAK_" + POISON, "ts_epoch": 104, "elapsed_s": 4}]
    telemetry = tmp_path / "raw" / "htb-synthetic" / "telemetry.jsonl"
    _write_events(telemetry, rows)
    with pytest.raises(PROJECTOR.ProjectionFailure) as caught:
        PROJECTOR.project(telemetry, private, now=110)
    assert caught.value.code == "unknown_event"
    assert POISON not in str(caught.value)


def test_active_pointer_is_authoritative_not_mtime(tmp_path, keys):
    _, private_path, public_path = keys
    raw, safe = tmp_path / "raw", tmp_path / "safe"
    active = raw / "htb-active"
    newer = raw / "htb-newer-mtime"
    _write_events(active / "telemetry.jsonl", _rows())
    _write_events(newer / "telemetry.jsonl", _rows(blocked=True))
    (raw / "active-run.ref").write_text("htb-active\n")
    payload = PROJECTOR.project_active(raw, safe, private_path, now=110)
    assert payload["execution"]["blocked_attempts"] == 0
    assert READER.read_signed(safe / "latest.json", public_path) == payload


def test_missing_active_pointer_emits_signed_block(tmp_path, keys):
    _, private_path, public_path = keys
    raw, safe = tmp_path / "raw", tmp_path / "safe"
    raw.mkdir()
    payload = PROJECTOR.project_active(raw, safe, private_path, now=110)
    assert payload["observer"] == {
        "state": "blocked", "reason_code": "no_active_run", "records_accepted": 0,
        "records_rejected": 0, "unknown_event_count": 0,
    }
    assert READER.read_signed(safe / "latest.json", public_path) == payload


def test_pointer_traversal_is_rejected(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "active-run.ref").write_text("../htb-escape\n")
    with pytest.raises(PROJECTOR.ProjectionFailure, match="active_pointer_invalid"):
        PROJECTOR._read_pointer(raw)
