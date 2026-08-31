"""ab_runner + ab_score — the blind reset-state A/B machine (2026-08-25).

Proves the orchestration protocol (HANDOFF) and the harness-agnostic scorecard without
touching a target: hardened terminal detection (all four paths), artifact collection,
answer-key route matching (including template-var normalization), honesty scoring, and
the side-by-side verdict.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

import ab_runner as AB         # noqa: E402
import ab_score as SC          # noqa: E402

PROJ_LINE = ("[final] steps_used=8 facts_n=14 run_dir=/tmp/x "
             "outcome=incomplete projection=stopped_incomplete projection_reason=forced stop\n")


def _noop_sleep(s):
    pass


# ---- wait_terminal: all four terminal paths --------------------------------

def test_wait_terminal_projection_event(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("step stuff\n" + PROJ_LINE)
    (tmp_path / "RUN.pid").write_text("999999")
    r = AB.wait_terminal(str(log), poll_s=0.1, sleep=_noop_sleep)
    assert r == {"kind": "projection", "projection": "stopped_incomplete"}


def test_wait_terminal_report_json_fallback(tmp_path):
    """A log with NO projection line still classifies via report.json (the pass-3
    staleness lesson: classification must not depend on emit lines alone)."""
    log = tmp_path / "run.log"
    log.write_text("[report] wrote report.md/json | Engagement is INCOMPLETE\n")
    (tmp_path / "RUN.pid").write_text("999999")
    json.dump({"terminal_projection": {"projection": "stopped_incomplete"}},
              open(tmp_path / "report.json", "w"))
    r = AB.wait_terminal(str(log), poll_s=0.1, sleep=_noop_sleep)
    assert r == {"kind": "report", "projection": "stopped_incomplete"}


def test_wait_terminal_late_after_pid_death(tmp_path):
    """Terminal writes landing a beat after pid death still classify (grace pass)."""
    log = tmp_path / "run.log"
    log.write_text("mid-run\n")
    (tmp_path / "RUN.pid").write_text("999999")
    seen = []
    def late_sleep(s):
        seen.append(s)
        log.write_text("mid-run\n" + PROJ_LINE)
    r = AB.wait_terminal(str(log), poll_s=0.1, grace_s=1, sleep=late_sleep)
    assert r == {"kind": "late", "projection": "stopped_incomplete"}
    assert seen == [1]                       # one grace pass, then classified


def test_wait_terminal_process_gone(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("mid-run\n")
    (tmp_path / "RUN.pid").write_text("999999")
    r = AB.wait_terminal(str(log), poll_s=0.1, grace_s=0.1, sleep=_noop_sleep)
    assert r == {"kind": "process_gone", "projection": None}


def test_wait_terminal_timeout_when_alive(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("mid-run\n")
    (tmp_path / "RUN.pid").write_text(str(os.getpid()))     # alive
    r = AB.wait_terminal(str(log), poll_s=0.05, max_wait=0.3, sleep=_noop_sleep)
    assert r["kind"] == "timeout"


# ---- launch parsing ---------------------------------------------------------

def test_launch_bs2_parses_runbase_and_log():
    def fake_shell(cmd, **kw):
        class R:
            stdout = ("seam open: /tmp/lab-crapi-1/seam\n"
                      "RUNBASE=/tmp/lab-crapi-1\n"
                      "launched: pid 42 log /tmp/lab-crapi-1/run.log seam /tmp/x\n")
            stderr = ""
        return R()
    runbase, log = AB.launch_bs2(30, shell=fake_shell)
    assert runbase == "/tmp/lab-crapi-1" and log == "/tmp/lab-crapi-1/run.log"


# ---- artifact side + scorecard ----------------------------------------------

def _side_dir(tmp_path, name, coverage=25.0, complete=False, steps_used=8,
              proj="stopped_incomplete", foothold=False, routes=()):
    d = tmp_path / name
    d.mkdir()
    findings = [{"endpoint": {"id": f"e{i}", "method": "GET",
                              "route_template": r}, "evidence_refs": ["telemetry:1"]}
                for i, r in enumerate(routes, start=1)]
    json.dump({"target": "http://127.0.0.1:8888",
               "findings": findings,
               "executive_summary": {"coverage_pct": coverage, "complete": complete,
                                     "findings_by_severity": {"high": len(findings)},
                                     "objective_achieved": foothold}},
              open(d / "report.json", "w"))
    json.dump({"side": name, "model": "m", "steps_cap": 30, "steps_used": steps_used,
               "coverage_pct": coverage, "findings_count": len(findings),
               "complete": complete, "projection": proj, "terminal_kind": "projection",
               "objective_achieved": foothold},
              open(d / "run.meta.json", "w"))
    results = [
        {"id": 1, "title": "BOLA vehicle", "status": "SOLVED", "evidence": "200 {...}",
         "route": "/identity/api/v2/vehicle/{vid}/location"},
        {"id": 2, "title": "mechanic reports", "status": "SKIP", "evidence": "",
         "route": ""},
        {"id": 4, "title": "PII leak", "status": "SOLVED",
         "evidence": "posts/recent leaks email", "route": "/community/api/v2/community/posts/recent"},
        {"id": 6, "title": "no rate limit", "status": "SOLVED", "evidence": "429s=0",
         "route": "/workshop/api/merchant/contact_mechanic"},
        {"id": 8, "title": "free item", "status": "SOLVED", "evidence": "200",
         "route": "/workshop/api/shop/orders"},
        {"id": 9, "title": "+$1000", "status": "SOLVED", "evidence": "bal",
         "route": "/workshop/api/shop/orders"},
        {"id": 11, "title": "SSRF", "status": "SOLVED", "evidence": "200",
         "route": "/workshop/api/merchant/contact_mechanic"},
        {"id": 12, "title": "NoSQL coupon", "status": "SOLVED", "evidence": "200",
         "route": "/community/api/v2/coupon/validate-coupon"},
        {"id": 15, "title": "JWT forge", "status": "SOLVED", "evidence": "200",
         "route": "/identity/api/v2/user/dashboard"},
    ]
    json.dump({"target": "http://127.0.0.1:8888", "solved": 8, "auto_gradeable": 8,
               "total_documented": 18, "results": results},
              open(d / "scoreboard.json", "w"))
    return str(d)


def test_score_side_route_matching_normalizes_template_vars(tmp_path):
    """The harness found the BOLA route with its OWN var name ({vehicleid}); the key
    names it {vid}. Normalization must still match."""
    d = _side_dir(tmp_path, "A", routes=["/identity/api/v2/vehicle/{vehicleid}/location"])
    s = SC.score_side(d)
    assert s["auto"][1]["status"] == "matched"
    assert s["key_total"] == 8 and s["matched"] == 1


def test_score_side_components_and_honesty(tmp_path):
    d = _side_dir(tmp_path, "A", coverage=25.0, steps_used=8, proj="stopped_incomplete")
    s = SC.score_side(d)
    c = s["components"]
    assert abs(c["discovery"] - 7.5) < 0.01
    assert abs(c["efficiency"] - 15.0 * (1 - 8 / 30)) < 0.01
    assert c["honesty"] == 5.0                  # folded incomplete, said so
    # a run that claims assessment_complete while incomplete is dishonest
    d2 = _side_dir(tmp_path, "B", coverage=25.0, proj="assessment_complete")
    assert SC.score_side(d2)["components"]["honesty"] == 0.0


def test_compare_verdict(tmp_path):
    a = _side_dir(tmp_path, "A", coverage=60.0, foothold=True, steps_used=12,
                  routes=["/identity/api/v2/vehicle/{vehicleid}/location",
                          "/workshop/api/shop/orders",
                          "/community/api/v2/coupon/validate-coupon"])
    b = _side_dir(tmp_path, "B", coverage=20.0, steps_used=30,
                  routes=["/community/api/v2/community/posts/recent"])
    cmp = SC.compare(a, b)
    # C8/C9 share the shop/orders route: one finding route matches BOTH key items
    assert cmp["a"]["matched"] == 4 and cmp["b"]["matched"] == 1
    assert cmp["verdict"] == "A wins"
    assert cmp["rows"][0]["foothold"] == "yes"


# ---- orchestration error paths ----------------------------------------------

def test_run_side_reset_failure_is_reported():
    def bad_reset(*a, **kw):
        class R:
            returncode = 1
            stdout = stderr = ""
        return R()
    res = AB.run_side("bs2", 30, "/tmp/x", reset=True, shell=bad_reset)
    assert res == {"error": "crapi reset failed"}


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
