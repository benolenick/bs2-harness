"""Pass-7: deterministic web fact extraction — the pass-6 canary showed the flash
trooper looping to cap without a VERDICT while the salvage path recovered NOTHING
from transcripts that contained the whole crAPI identity. Pass 4 folded app=crapi
plus five enum= receipts from the VERDICT path on the same board; pass 6 folded
zero because salvage had no web patterns. These pin the three fixes: curl
descriptor probes derive enum receipts, web titles salvage as app= facts, and the
engine's own [auto-searchsploit] chunks can't masquerade as a target wall."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

from trooper import _derive_enum_facts, _salvage_facts, _diagnose_blocked  # noqa: E402

CRAPI_ROOT = """$ curl -i http://127.0.0.1:8888/
HTTP/1.1 200 OK
Server: openresty/1.27.1.2
Content-Type: text/html

<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>crAPI</title>
<meta name="description" content="completely ridiculous API (crAPI) ..."/>
</head><body><div id="root"></div></body></html>
"""


def test_curl_descriptor_probes_derive_enum_receipts():
    cmds = [
        "curl -s http://127.0.0.1:8888/openapi.json",
        "curl -sk http://127.0.0.1:8888/v3/api-docs | head -c 500",
        "curl -s http://127.0.0.1:8888/swagger-ui/",
        "curl -i http://127.0.0.1:8888/",
        "curl -s http://127.0.0.1:8888/static/js/main.8c78208c.js | grep -oE '/[a-z-]+' | head -50",
    ]
    facts = _derive_enum_facts(cmds)
    assert "enum=8888:api-surface" in facts
    assert "enum=8888:tech-fingerprint" in facts
    assert "enum=8888:js-endpoints" in facts


def test_plain_curl_to_route_derives_nothing():
    facts = _derive_enum_facts(["curl -s http://127.0.0.1:8888/login"])
    assert facts == []


def test_salvage_extracts_app_from_html_title():
    facts = _salvage_facts([CRAPI_ROOT], "127.0.0.1")
    assert "app=crapi" in facts


def test_salvage_juice_shop_title():
    facts = _salvage_facts(["<html><head><title>Juice Shop</title></head></html>"], "")
    assert "app=juice-shop" in facts


def test_salvage_no_false_app_for_generic_titles():
    for title in ("Login", "Home", "Error", "Sign in", "Admin", "Welcome", "Test"):
        facts = _salvage_facts([f"<html><title>{title}</title></html>"], "")
        assert not [f for f in facts if f.startswith("app=")], f"false app= from {title!r}"


def test_salvage_keeps_existing_signal_extraction():
    facts = _salvage_facts([CRAPI_ROOT, "$ ssh 198.51.100.10\ngetuid: root\n"], "198.51.100.10")
    assert "app=crapi" in facts
    assert "rce_as=root" in facts


def test_diagnose_ignores_engine_searchsploit_chunk():
    t = ("$ searchsploit openresty | head -n 20\n"
         "[auto-searchsploit openresty]\nExploits: No Results\n\n"
         "$ curl -i http://127.0.0.1:8888/\nHTTP/1.1 200 OK\n")
    assert _diagnose_blocked(t) == ""


def test_diagnose_ignores_model_run_searchsploit_no_results():
    # the model's OWN searchsploit run (unlabelled) must also not read as the
    # target's "no results" wall
    t = "$ searchsploit openresty | head -n 20\nExploits: No Results\n"
    assert _diagnose_blocked(t) == ""


def test_diagnose_still_matches_real_no_results_wall():
    t = "$ curl -s http://127.0.0.1:8888/api/x\nno results\n"
    assert "no_matching_module" in _diagnose_blocked(t)


def test_diagnose_still_matches_msf_module_failures():
    t = "$ msfconsole -x 'use exploit/linux/http/fake; run'\n[-] Failed to load module: exploit/linux/http/fake\n"
    assert "no_matching_module" in _diagnose_blocked(t)


if __name__ == "__main__":
    for fn in (test_curl_descriptor_probes_derive_enum_receipts,
               test_plain_curl_to_route_derives_nothing,
               test_salvage_extracts_app_from_html_title,
               test_salvage_juice_shop_title,
               test_salvage_no_false_app_for_generic_titles,
               test_salvage_keeps_existing_signal_extraction,
               test_diagnose_ignores_engine_searchsploit_chunk,
               test_diagnose_ignores_model_run_searchsploit_no_results,
               test_diagnose_still_matches_real_no_results_wall,
               test_diagnose_still_matches_msf_module_failures):
        fn()
        print("ok", fn.__name__)
