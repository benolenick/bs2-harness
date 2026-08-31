import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("lenz_harness", ROOT / "manager" / "lenz_harness.py")
HARNESS = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(HARNESS)


def test_safe_stream_accepts_only_structural_events(tmp_path):
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    stream.manager(1, "RUN", 3, True)
    stream.ran(1, 2.5, 2, False)
    stream.finding(1, True)
    stream.stop(1)
    rows = [json.loads(line) for line in stream.path.read_text().splitlines()]
    assert [row["event"] for row in rows] == ["boot", "manager", "ran", "finding", "stop"]
    assert rows[3]["evidence_refs"] == ["bound"]


def test_native_translation_ignores_prose_and_unknown_events(tmp_path):
    poison = "target=example.invalid command=curl secret=hunter2"
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    assert stream.observe("seeded", source=poison, n=3) is None
    stream.observe("manager", step=1, verb="TASK", routes=2, memoria=True,
                   action=poison, why=poison)
    stream.observe("ran", step=1, secs=4, cmds=2, blocked="auth wall", marker=poison)
    stream.observe("finding", step=1, evidence_refs=[poison], text=poison)
    stream.observe("report", step=1, prose=poison)
    stream.stop(1)
    translated = stream.path.read_text()
    assert poison not in translated
    rows = [json.loads(line) for line in translated.splitlines()]
    assert [row["event"] for row in rows] == ["boot", "manager", "ran", "finding", "report"]
    assert rows[1]["verb"] == "RUN"
    assert rows[2]["blocked"] is True


def test_plain_language_translation_has_no_free_text_input(tmp_path):
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    stream.translate(1, "feed", "feed_update", 7, 3, "memory_available")
    row = json.loads(stream.path.read_text().splitlines()[-1])
    assert row["event"] == "translation"
    assert row == {**row, "channel": "feed", "code": "feed_update", "count": 7,
                   "count2": 3, "status": "memory_available"}
    assert not any(key in row for key in ("text", "command", "target", "marker", "reason"))
    stream.stop()


def test_null_lenz_noops_everything():
    # GB_LENZ=0 default: the manager loop uses NullLenz, so no emit/translate/stop can
    # ever raise (Ben 2026-08-25: the mirror is only for Codex consumers).
    n = HARNESS.NullLenz()
    assert n.observe("manager", step=1, verb="TASK", routes=2, memoria=True) is None
    assert n.translate(1, "manager", "manager_action", 0, 0, "autoturret") is None
    assert n.stop(1) is None


def test_translation_accepts_autoturret_status(tmp_path):
    # REGRESSION (run 750 crash x2): the AUTOTURRET manager verb maps to status
    # "autoturret" in run_htb's lenz bridge; TRANSLATION_STATUSES must admit it or
    # emit() raises ValueError and kills the whole engagement.
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    stream.translate(1, "manager", "manager_action", 0, 0, "autoturret")
    row = json.loads(stream.path.read_text().splitlines()[-1])
    assert row["status"] == "autoturret"
    stream.stop()


def test_translation_rejects_unsanitized_direct_emit(tmp_path):
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    with pytest.raises(ValueError):
        stream.emit("translation", step=1, channel="manager", code="manager_action",
                    count=0, count2=0, status="run", text="curl http://10.0.0.1/x")
    stream.stop()


@pytest.mark.parametrize("event,fields", [
    ("manager", {"step": 1, "verb": "RUN", "routes": 2, "memoria": True, "detail": "raw"}),
    ("ran", {"step": 1, "secs": 1, "cmds": 1, "blocked": "false"}),
    ("finding", {"step": 1, "evidence_refs": ["target-derived-id"]}),
])
def test_safe_stream_rejects_text_and_bad_shapes(tmp_path, event, fields):
    stream = HARNESS.SafeLenzStream(tmp_path / "htb-synthetic", 8)
    with pytest.raises(ValueError):
        stream.emit(event, **fields)
    stream.stop()


def test_publish_is_atomic_and_pointer_contains_name_only(tmp_path):
    raw = tmp_path / "raw"
    run = raw / "htb-synthetic"
    run.mkdir(parents=True)
    (run / "telemetry.jsonl").write_text("safe\n")
    HARNESS.publish_active_run(run, raw_root=raw)
    assert (raw / "active-run.ref").read_text() == "htb-synthetic\n"
    assert not list(raw.glob(".active-run.ref.*"))
