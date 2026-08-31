"""governed_runner — the governed HTTP transport for the differential/lab engines
(re-audit P1-2 vertical slice): request_spec -> curl through the §10.1 door ->
normalized response. Cookie jars ride as REFS; header values never enter records."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

import governed_runner as GR                        # noqa: E402

SPEC = {
    "method": "GET",
    "base": "http://127.0.0.1:8888",
    "route_template": "/identity/api/v2/vehicle/{id}/location",
    "path_binding": {"id": "vehicle-1"},
    "session_ref": {"cookies": "/run/principal-jars/user-a.cookies"},
}


def test_compile_curl_binds_template_and_jar_ref():
    cmd = GR.compile_curl(SPEC)
    assert "vehicle-1" in cmd
    assert "{id}" not in cmd
    assert "-b" in cmd and "user-a.cookies" in cmd
    assert "-X" in cmd and "GET" in cmd
    assert "curl" in cmd.split()[0]


def test_compile_curl_header_values_only_in_command():
    cmd = GR.compile_curl({**SPEC, "headers": {"Authorization": "Bearer SECRET"}})
    assert "Bearer SECRET" in cmd          # transport must authenticate
    # but a parse never surfaces values — only names
    out = "HTTP/1.1 200 OK\r\nAuthorization: Bearer SECRET\r\nContent-Type: application/json\r\n\r\n{}"
    rec = GR.parse_response(out)
    assert "authorization" in rec["headers"] and "content-type" in rec["headers"]


def test_parse_response_normalized_record():
    out = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Rate-Limit: 100\r\n\r\n"
           "{\"id\":\"vehicle-1\",\"smart_location\":\"x\"}\n__GB_STATUS__:200 __GB_TIME__:0.041")
    rec = GR.parse_response(out)
    assert rec["status"] == 200
    assert rec["schema_keys"] == ["id", "smart_location"]
    assert rec["headers"]["x-rate-limit"] == "100"
    assert 39.0 < rec["ms"] < 43.0
    assert "__GB_STATUS__" not in rec["body"]


def test_parse_response_denied_marker():
    rec = GR.parse_response("[GOVERNED DENY: risk 'medium' exceeds capability ceiling 'low']")
    assert rec["status"] == 0 and "GOVERNED DENY" in rec["error"]


def test_make_runner_goes_through_governed_door():
    calls = {}

    def fake_run(cmd, target=None, **kw):
        calls["cmd"], calls["target"], calls["cls"] = cmd, target, kw.get("action_class")
        return ("HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}\n__GB_STATUS__:200 __GB_TIME__:0.02")
    runner = GR.make_runner(timeout=15, target_exec_run=fake_run)
    rec = runner(SPEC)
    assert rec["status"] == 200 and rec["schema_keys"] == ["ok"]
    assert calls["cls"] == "web.recon" and calls["target"] == "http://127.0.0.1:8888"
    assert "vehicle-1" in calls["cmd"]


def test_runner_works_with_differential_replay():
    import differential as DIFF

    def fake_run(cmd, target=None, **kw):
        return ("HTTP/1.1 200 OK\r\n\r\n{\"id\":\"v1\",\"balance\":9}\n"
                "__GB_STATUS__:200 __GB_TIME__:0.02")
    runner = GR.make_runner(target_exec_run=fake_run)
    spec = DIFF.request_spec({"method": "GET", "route_template": "/api/x/{id}",
                              "vhost": ""}, {"principal": "anon", "refs": {}})
    rec = DIFF.replay(spec, runner)
    assert rec["status"] == 200 and rec["schema_keys"] == ["balance", "id"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
