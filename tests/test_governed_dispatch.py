"""governed executor ssh-dispatch (2026-08-25): the §10.1 single door now reaches the
exec host (your-host, where tun0 lives) via GB_GOVERNED_HOST + GB_GOVERNED_SEAM_DIR.
Fail-closed everywhere: incomplete config refuses, errors return markers, and a refused
governed route NEVER falls back to the ungoverned shell."""
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

import target_exec as TEXEC                       # noqa: E402


def _clear_governed_env(monkeypatch):
    for k in ("BS2_SEAM_RUN", "GB_GOVERNED_HOST", "GB_GOVERNED_SEAM_DIR",
              "GB_GOVERNED_SEAM_PY", "GB_TARGET_AUDIT", "GB_RAW_LOG"):
        monkeypatch.delenv(k, raising=False)


def _audit_lines(path):
    return [json.loads(l) for l in open(path) if l.strip()]


def test_governed_target_resolution(monkeypatch):
    _clear_governed_env(monkeypatch)
    assert TEXEC._governed_target()["mode"] == "off"
    seam = tempfile.mkdtemp()
    monkeypatch.setenv("BS2_SEAM_RUN", seam)
    assert TEXEC._governed_target() == {"mode": "local", "seam": seam}
    monkeypatch.setenv("GB_GOVERNED_HOST", "your-host")
    assert TEXEC._governed_target()["mode"] == "remote"
    assert TEXEC._governed_target()["host"] == "your-host"
    assert TEXEC._governed_target()["seam"] == seam     # BS2_SEAM_RUN doubles as remote path
    monkeypatch.delenv("BS2_SEAM_RUN")
    assert TEXEC._governed_target()["mode"] == "refused"


def test_remote_dispatch_argv_and_audit(monkeypatch):
    _clear_governed_env(monkeypatch)
    audit = tempfile.mktemp()
    monkeypatch.setenv("GB_GOVERNED_HOST", "your-host")
    monkeypatch.setenv("GB_GOVERNED_SEAM_DIR", "/srv/seam/run-1")
    monkeypatch.setenv("GB_GOVERNED_SEAM_PY", "/opt/bs2/live/governed_seam.py")
    monkeypatch.setenv("GB_TARGET_AUDIT", audit)
    captured = {}
    def fake_run(argv, **kw):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(TEXEC.subprocess, "run", fake_run)
    out = TEXEC.run("whoami", action_class="web.recon")
    argv = captured["argv"]
    assert argv[:2] == ["ssh", "-o"]
    assert argv[-2] == "your-host"
    remote_line = argv[-1]
    assert remote_line.startswith("python3 /opt/bs2/live/governed_seam.py exec")
    assert "--run-dir /srv/seam/run-1 --class web.recon --risk low -- bash -lc whoami" in remote_line
    assert out == "ok"
    recs = _audit_lines(audit)
    assert recs[-1]["mode"] == "governed" and recs[-1]["host"] == "remote:your-host"
    assert recs[-1]["result"] == "allowed"


def test_remote_default_seam_py(monkeypatch):
    _clear_governed_env(monkeypatch)
    monkeypatch.setenv("GB_GOVERNED_HOST", "your-host")
    monkeypatch.setenv("GB_GOVERNED_SEAM_DIR", "/srv/seam/run-1")
    captured = {}
    def fake_run(argv, **kw):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(TEXEC.subprocess, "run", fake_run)
    TEXEC.run("id", action_class="web.recon")
    assert "~/gunbelt/live/governed_seam.py" in captured["argv"][-1]


def test_risk_derived_from_impact(monkeypatch):
    """The door rates commands on the seam's impact axis: read->low, mutate->medium.
    An unwitnessed (low-ceiling) seam therefore allows read-only recon and denies
    mutations — the vocabulary mismatch that denied EVERYTHING in lab pass 1."""
    _clear_governed_env(monkeypatch)
    seam = tempfile.mkdtemp()
    monkeypatch.setenv("BS2_SEAM_RUN", seam)
    seen = {}
    def fake_run(argv, **kw):
        seen["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(TEXEC.subprocess, "run", fake_run)
    TEXEC.run("curl -s http://127.0.0.1:3006/", action_class="web.recon")
    assert seen["argv"][seen["argv"].index("--risk") + 1] == "low"
    TEXEC.run("curl -s -X POST --data 'a=b' http://127.0.0.1:3006/x", action_class="web.recon")
    assert seen["argv"][seen["argv"].index("--risk") + 1] == "medium"


def test_remote_config_refused_never_falls_back(monkeypatch):
    _clear_governed_env(monkeypatch)
    monkeypatch.setenv("GB_GOVERNED_HOST", "your-host")      # no seam dir -> refused
    monkeypatch.setattr(TEXEC, "_capture", lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("ungoverned shell must never run when governance was requested")))
    out = TEXEC.run("whoami")
    assert out.startswith("[GOVERNED CONFIG (fail-closed, not run):")


def test_remote_fail_closed_on_ssh_error(monkeypatch):
    _clear_governed_env(monkeypatch)
    monkeypatch.setenv("GB_GOVERNED_HOST", "your-host")
    monkeypatch.setenv("GB_GOVERNED_SEAM_DIR", "/srv/seam/run-1")
    def boom(argv, **kw):
        raise subprocess.TimeoutExpired("ssh", 5)
    monkeypatch.setattr(TEXEC.subprocess, "run", boom)
    out = TEXEC.run("whoami")
    assert out.startswith("[GOVERNED ERROR (fail-closed, not run):")


def test_remote_deny_marker(monkeypatch):
    _clear_governed_env(monkeypatch)
    monkeypatch.setenv("GB_GOVERNED_HOST", "your-host")
    monkeypatch.setenv("GB_GOVERNED_SEAM_DIR", "/srv/seam/run-1")
    monkeypatch.setattr(TEXEC.subprocess, "run", lambda argv, **kw:
                        SimpleNamespace(returncode=1, stdout="",
                                        stderr="impact critical: denied"))
    # use a NON-destructive command: the destructive-command guard runs before the governed
    # dispatch, so `rm` would be blocked by that guard first and never reach the deny marker.
    out = TEXEC.run("id")
    assert out.startswith("[GOVERNED DENY: impact critical: denied")


def test_local_seam_unchanged(monkeypatch):
    _clear_governed_env(monkeypatch)
    seam = tempfile.mkdtemp()
    monkeypatch.setenv("BS2_SEAM_RUN", seam)
    captured = {}
    def fake_run(argv, **kw):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(TEXEC.subprocess, "run", fake_run)
    out = TEXEC.run("whoami", action_class="web.recon")
    argv = captured["argv"]
    assert argv[0] == "python3"
    assert argv[1].endswith("governed_seam.py")
    assert argv[2:4] == ["exec", "--run-dir"] and argv[4] == seam
    assert out == "ok"


def test_off_falls_back_to_witnessed(monkeypatch):
    _clear_governed_env(monkeypatch)
    audit = tempfile.mktemp()
    monkeypatch.setenv("GB_TARGET_AUDIT", audit)
    captured = {}
    def fake_capture(argv, timeout):
        captured["argv"] = argv
        return "localout"
    monkeypatch.setattr(TEXEC, "_capture", fake_capture)
    out = TEXEC.run("echo hi")
    assert out == "localout"
    assert captured["argv"] == ["bash", "-lc", "echo hi"]
    assert _audit_lines(audit)[-1]["mode"] == "ungoverned"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
