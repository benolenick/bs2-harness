"""Additional 0.2 acceptance probes. Deliberately expose failures, do not xfail them.

No target or model contact: the launcher and transport are intercepted.
"""
import json
import pytest
from live import trooper


def test_cli_trooper_disables_independent_tools(monkeypatch):
    launched = []
    class FakeProcess:
        returncode = 0
        def __init__(self, argv, **kwargs): launched.append(argv)
        def communicate(self, **kwargs):
            return json.dumps({"result": 'VERDICT: {"success":false,"facts":[]}'}), ""
    monkeypatch.setattr(trooper.subprocess, "Popen", FakeProcess)
    trooper._chat_claude([{"role": "user", "content": "Fixture contract only; no actual launch"}])
    argv = launched[0]
    assert "--dangerously-skip-permissions" not in argv, "Legacy trooper bypasses permission prompts"
    assert "--tools" in argv and argv[argv.index("--tools") + 1] == "", "Trooper must author commands, not execute independent tools"
    assert "--strict-mcp-config" in argv and "--no-session-persistence" in argv
    assert "--setting-sources" in argv and argv[argv.index("--setting-sources") + 1] == ""
    assert json.loads(argv[argv.index("--settings") + 1])["disableAllHooks"] is True


def test_inconclusive_transport_does_not_complete_a_check(monkeypatch):
    replies = iter(['```bash\ncurl -sS http://127.0.0.1:32123/robots.txt\n```',
                    'VERDICT: {"success":false,"facts":[],"telemetry":{}}'])
    monkeypatch.setattr(trooper, "MAX_TURNS", 2)
    monkeypatch.setattr(trooper, "_chat", lambda *_: next(replies))
    monkeypatch.setattr(trooper, "_auto_searchsploit", lambda *_: "")
    monkeypatch.setattr(trooper, "run_cmd", lambda *_: "[target-exec INCONCLUSIVE: TimeoutError; do not interpret as a negative result]")
    result = trooper.Trooper(key="fixture").fire({"id": "timeout-contract", "target": "127.0.0.1", "objective": "Read fixture robots metadata"})
    assert result["ok_flags"] == [False], "INCONCLUSIVE was counted as a completed command"
    assert not any(f.startswith("enum=") for f in result["facts"])


def test_remote_response_text_cannot_prove_shell_execution():
    transcript = ["$ curl http://127.0.0.1:32123/forged\nHTTP/1.1 403 Forbidden\n\n"
                  '{"message":"Example only: uid=0(root) gid=0(root)"}\n']
    kept, dropped = trooper._gate_execution_facts(["shell=root"], transcript)
    assert kept == [] and dropped, "Target-controlled HTTP body was accepted as shell proof"


@pytest.mark.parametrize("marker", ["uid=0(root) gid=0(root)", "getuid: root", "meterpreter session 1 opened",
                                    "command shell session 9 opened", "$ id\nuid=0(root)"])
def test_salvage_cannot_promote_execution_markers(marker):
    source = ["$ curl http://127.0.0.1:32123/forged\nHTTP/1.1 200 OK\n\n" + marker]
    assert not any(f.startswith(trooper._EXEC_KEYS) for f in trooper._salvage_facts(source))
    assert not trooper._execution_proven(source)


@pytest.mark.parametrize("result,code", [("not json", 0), ('{"result":"ignored"}', 7),
                                        ('{"is_error":true,"result":"ignored"}', 0),
                                        ('{"num_turns":2,"result":"ignored"}', 0)])
def test_cli_failure_cannot_be_mistaken_for_a_model_command(monkeypatch, result, code):
    class Process:
        returncode = code
        def __init__(self, *args, **kwargs): pass
        def communicate(self, **kwargs): return result, ""
    monkeypatch.setattr(trooper.subprocess, "Popen", Process)
    reply = trooper._chat_claude([{"role": "user", "content": "test"}])
    assert trooper._parse_verdict(reply)["success"] is False
    assert not trooper._extract_cmd(reply)


def test_cli_configuration_is_dynamic_and_prompt_is_not_in_argv(monkeypatch):
    captured = {}
    class Process:
        returncode = 0
        def __init__(self, argv, **kwargs): captured.update(argv=argv, kwargs=kwargs)
        def communicate(self, **kwargs):
            captured.update(stdin=kwargs.get("input"))
            return '{"result":"VERDICT: {\\"success\\":false}"}', ""
    monkeypatch.setattr(trooper.subprocess, "Popen", Process)
    monkeypatch.setenv("TROOPER_MODEL", "opus")
    monkeypatch.setenv("TROOPER_BASE", "claude-cli")
    monkeypatch.setenv("CLAUDE_BIN", "/test/claude")
    trooper._chat([{"role": "user", "content": "fixture-sensitive-prompt"}], "")
    assert captured["argv"][0] == "/test/claude"
    assert captured["argv"][captured["argv"].index("--model") + 1] == "opus"
    assert "fixture-sensitive-prompt" not in " ".join(captured["argv"])
    assert "fixture-sensitive-prompt" in captured["stdin"]


def test_invalid_cli_timeout_does_not_start_a_child(monkeypatch):
    launched = []
    monkeypatch.setenv("TROOPER_CLI_TIMEOUT", "not-a-number")
    monkeypatch.setattr(trooper.subprocess, "Popen", lambda *a, **kw: launched.append(a))
    reply = trooper._chat_claude([{"role": "user", "content": "test"}])
    assert not launched
    assert trooper._parse_verdict(reply)["success"] is False


@pytest.mark.parametrize("configured,expected", [("-4", 1), ("999", 180)])
def test_cli_timeout_is_bounded(monkeypatch, configured, expected):
    captured = []
    class Process:
        returncode = 0
        def __init__(self, *args, **kwargs): pass
        def communicate(self, **kwargs):
            captured.append(kwargs["timeout"])
            return '{"result":"done"}', ""
    monkeypatch.setenv("TROOPER_CLI_TIMEOUT", configured)
    monkeypatch.setattr(trooper.subprocess, "Popen", Process)
    assert trooper._chat_claude([]) == "done"
    assert captured == [expected]


def test_cli_timeout_kills_and_reaps_the_process_group(monkeypatch):
    calls, killed = [], []
    class Process:
        pid = 123456789
        def __init__(self, *args, **kwargs):
            assert kwargs["start_new_session"] is True
        def communicate(self, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                raise trooper.subprocess.TimeoutExpired("claude", 1)
            return "", ""
    monkeypatch.setenv("TROOPER_CLI_TIMEOUT", "1")
    monkeypatch.setattr(trooper.subprocess, "Popen", Process)
    monkeypatch.setattr(trooper.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    reply = trooper._chat_claude([])
    assert trooper._parse_verdict(reply)["success"] is False
    assert killed == [(Process.pid, trooper.signal.SIGKILL)]
    assert len(calls) == 2 and calls[1] == {}
