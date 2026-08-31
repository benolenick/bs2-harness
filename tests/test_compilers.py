import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "live"))

from adapters.compilers import (playwright_capture_recipe, schemathesis_compile,
                                zap_report_compile)
from adapters.playwright import adapt as playwright_adapt


def _fixture(name):
    with open(os.path.join(HERE, "fixtures", name)) as handle:
        return handle.read()


def test_schemathesis_cli_compiles_failures():
    report = schemathesis_compile(_fixture("schemathesis_failure.txt"))
    assert [(failure["method"], failure["endpoint"], failure["check"])
            for failure in report["failures"]] == [
        ("GET", "/api/accounts/{id}", "response_schema_conformance"),
        ("POST", "/api/transfer", "not_a_server_error"),
    ]
    assert all("curl" in failure["example"] for failure in report["failures"])


def test_playwright_recipe_and_recorded_dump_match_adapter_contract():
    snippet = playwright_capture_recipe(["/api/", "example.test"])
    assert "page.on('response'" in snippet
    assert all(field in snippet for field in ("url", "method", "status", "context"))
    events = json.loads(_fixture("playwright_events.json"))
    records = playwright_adapt(events, {"target": "localhost"})["records"]
    assert len(records) == 2
    assert all(not record.validate() for record in records)


def test_zap_traditional_json_needs_no_translation():
    report = {"@version": "fixture", "site": []}
    assert zap_report_compile(json.dumps(report)) == report
