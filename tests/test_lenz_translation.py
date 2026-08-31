import importlib.util
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


HARNESS = _load("lenz_harness_translation", ROOT / "manager" / "lenz_harness.py")
PROJECTOR = _load("lenz_projector_translation", ROOT / "manager" / "lenz_projector.py")
READER = _load("lenz_reader_translation", ROOT / "manager" / "lenz.py")


def test_typed_translation_round_trip_has_only_fixed_text(tmp_path):
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    stream.translate(1, "feed", "feed_update", 7, 3, "memory_available")
    stream.translate(1, "manager", "manager_action", 3, 0, "run")
    stream.translate(1, "hands", "hands_result", 2, 0, "completed")
    stream.stop(1)

    private = Ed25519PrivateKey.generate()
    payload = PROJECTOR.project(stream.path, private, now=stream.started + 10)
    envelope = PROJECTOR.sign(payload, private)
    signed = tmp_path / "signed.json"
    public = tmp_path / "public.pem"
    signed.write_text(json.dumps(envelope))
    public.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    read = READER.read_signed(signed, public)
    assert read["schema"] == "lenz/v3"
    assert read["translations"] == [
        {"step": 1, "channel": "feed",
         "text": "Manager received 7 mapped items and 3 routes; memory was available."},
        {"step": 1, "channel": "manager",
         "text": "Manager selected a run action with 3 routes visible."},
        {"step": 1, "channel": "hands",
         "text": "Hands completed 2 commands; result was completed."},
    ]


def test_reader_accepts_exact_legacy_v2_shape(tmp_path):
    private = Ed25519PrivateKey.generate()
    payload = PROJECTOR._empty(100.0, "no_active_run")
    payload["schema"] = "lenz/v2"
    payload.pop("translations")
    signed = tmp_path / "legacy.json"
    public = tmp_path / "public.pem"
    signed.write_text(json.dumps(PROJECTOR.sign(payload, private)))
    public.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert READER.read_signed(signed, public)["schema"] == "lenz/v2"
