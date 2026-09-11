"""0.2 breaking safety contract: legacy SSH/seam configuration cannot select a
shell fallback. The optional external seam package has its own opt-in suite."""
import pytest
from live import target_exec as te
from runtime_fixture import runtime_fixture


@pytest.mark.parametrize("config", [
    {"GB_GOVERNED_HOST": "operator@example.invalid"},
    {"GB_GOVERNED_HOST": "operator@example.invalid", "GB_GOVERNED_SEAM_DIR": "/missing"},
    {"BS2_SEAM_RUN": "/missing"},
    {"BS2_SEAM_RUN": "/tmp"},
    {"TROOPER_EXEC_SSH": "operator@example.invalid"},
])
def test_legacy_backends_fail_closed(tmp_path, monkeypatch, config):
    with runtime_fixture(tmp_path) as f:
        for key, value in config.items():
            monkeypatch.setenv(key, value)
        monkeypatch.setattr(te, "_capture", lambda *a: pytest.fail("uncontained subprocess"))
        result = te.run("curl " + f["base"] + "/whoami", f["base"])
        assert "no fallback" in result
        assert not f["contacts"] and not f["decisions"]


def test_no_policy_never_falls_back(monkeypatch):
    for key in te._HITL_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(te, "_capture", lambda *a: pytest.fail("uncontained subprocess"))
    assert "BLOCKED" in te.run("echo localout", "127.0.0.1")


def test_missing_local_seam_is_explicitly_refused(monkeypatch):
    monkeypatch.delenv("GB_GOVERNED_HOST", raising=False)
    monkeypatch.setenv("BS2_SEAM_RUN", "/does-not-exist-bs2")
    assert te._governed_target()["mode"] == "refused"
