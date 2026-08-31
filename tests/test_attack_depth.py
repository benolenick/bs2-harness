"""Attack depth + vhost verification — the 2026-08-25 fix batch:

1. Vhost facts born UNVERIFIED (off frontier, out of coverage); batch content-compare
   promotes reals (verified=) and kills ghosts (dead=). Closes the run-745 re-fuzz loop
   where ~19 wordlist ghosts were re-added to the frontier every step.
2. attack=<app>:<ritual> receipts derived from the transcript, keyed to the app the
   manager's objective names; self-reported attack= facts are stripped (proof-gate).
3. Depth floor: an identified app with no attack receipt blocks completion.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

from trooper import _derive_attack_facts, _strip_derived          # noqa: E402
from cartographer.core import Cartographer                        # noqa: E402
from cartographer.model import (DEAD, UNTOUCHED, UNVERIFIED)      # noqa: E402


def _mk_doc():
    return {
        "target": "10.0.0.1", "updated": 0, "log": [],
        "nodes": {
            "host:10.0.0.1": {
                "id": "host:10.0.0.1", "kind": "host", "label": "10.0.0.1",
                "state": UNTOUCHED, "rituals_done": ["full-port-sweep"],
                "touched_ts": 0, "meta": {"ip": "10.0.0.1"}},
            "port:10.0.0.1:80": {
                "id": "port:10.0.0.1:80", "kind": "port", "label": "80/http",
                "state": UNTOUCHED, "rituals_done": [], "touched_ts": 0,
                "meta": {"port": 80, "service": "http"}},
        },
    }


def _cartographer(doc):
    c = Cartographer(tempfile.mkdtemp())
    c.doc = doc
    return c


# ---- 1. vhost verification at ingestion ------------------------------------
def test_vhost_facts_born_unverified_and_off_frontier():
    c = _cartographer(_mk_doc())
    c.fold(["vhost=gitlab.inlanefreight.local", "vhost=support.inlanefreight.local"], ts=1)
    n = c.doc["nodes"]["vhost:gitlab.inlanefreight.local"]
    assert n["state"] == UNVERIFIED
    assert n["meta"].get("verify_pending") is True
    # unverified ghosts must NOT sit on the frontier...
    assert not any(r["id"].startswith("vhost:") for r in c.frontier())
    # ...and must NOT block completion (they are not surface yet)
    rep = c.coverage_report()
    assert "gitlab.inlanefreight.local" not in str(rep["blockers"])


def test_verified_promotes_and_dead_kills():
    c = _cartographer(_mk_doc())
    c.fold(["vhost=a.local", "vhost=b.local"], ts=1)
    c.fold(["verified=a.local"], ts=2)
    assert c.doc["nodes"]["vhost:a.local"]["state"] == UNTOUCHED
    assert "verify_pending" not in c.doc["nodes"]["vhost:a.local"]["meta"]
    c.fold(["dead=b.local"], ts=3)
    assert c.doc["nodes"]["vhost:b.local"]["state"] == DEAD
    # the promoted vhost IS on the frontier now
    assert any(r["id"] == "vhost:a.local" for r in c.frontier())


def test_remention_never_resurrects_a_dead_vhost():
    c = _cartographer(_mk_doc())
    c.fold(["vhost=x.local"], ts=1)
    c.fold(["dead=x.local"], ts=2)
    c.fold(["vhost=x.local"], ts=3)   # re-fuzz mentions it again
    assert c.doc["nodes"]["vhost:x.local"]["state"] == DEAD


def test_verified_only_promotes_unverified_vhosts():
    c = _cartographer(_mk_doc())
    c.fold(["vhost=x.local"], ts=1)
    c.fold(["dead=x.local"], ts=2)
    c.fold(["verified=x.local"], ts=3)   # a ghost must not resurrect via verified=
    assert c.doc["nodes"]["vhost:x.local"]["state"] == DEAD


# ---- 2+3. attack receipts + depth floor -------------------------------------
def _mk_app_doc():
    doc = _mk_doc()
    doc["nodes"]["app:gitlab"] = {
        "id": "app:gitlab", "kind": "app", "label": "gitlab 13.10",
        "state": UNTOUCHED, "rituals_done": [], "touched_ts": 0,
        "meta": {"app": "gitlab", "version": "13.10"}}
    return doc


def test_depth_floor_blocks_until_an_attack_receipt_lands():
    c = _cartographer(_mk_app_doc())
    rep = c.coverage_report()
    assert any("never attacked" in b for b in rep["blockers"])
    c.fold(["attack=gitlab:cve-lookup"], ts=1)
    assert c.doc["nodes"]["app:gitlab"]["rituals_done"] == ["cve-lookup"]
    rep = c.coverage_report()
    assert not any("never attacked" in b for b in rep["blockers"])
    assert rep["unattacked_apps"] == []


def test_attack_fact_on_wrong_node_or_bogus_ritual_noops():
    c = _cartographer(_mk_app_doc())
    c.fold(["attack=gitlab:totally-bogus"], ts=1)
    assert c.doc["nodes"]["app:gitlab"]["rituals_done"] == []
    # '80' matches the http PORT node, whose rituals don't include attack rituals -> no-op
    c.fold(["attack=80:cve-lookup"], ts=2)
    assert c.doc["nodes"]["port:10.0.0.1:80"]["rituals_done"] == []
    # unknown app name matches nothing -> no-op
    c.fold(["attack=wordpress:cve-lookup"], ts=3)
    assert c.doc["nodes"]["app:gitlab"]["rituals_done"] == []


def test_derive_attack_facts_from_transcript():
    cmds = [
        "searchsploit gitlab 13.10 | head -n 20",
        "msfconsole -q -x \"use exploit/multi/http/gitlab_file_read_rce; "
        "set RHOSTS 198.51.100.10; run; exit\"",
        "python3 /tmp/49979.py -u http://198.51.100.10:8080",
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt 198.51.100.10 "
        "http-post-form \"/login:user=^USER^&pass=^PASS^:F=incorrect\"",
    ]
    facts = _derive_attack_facts(cmds, "", "gitlab")
    assert "attack=gitlab:cve-lookup" in facts
    assert "attack=gitlab:known-exploit-chain" in facts
    assert "attack=gitlab:default-creds" in facts


def test_auto_searchsploit_chunk_counts_as_cve_lookup():
    out = "[auto-searchsploit gitlab]\nExploit: GitLab 13.10 RCE\n"
    assert "attack=gitlab:cve-lookup" in _derive_attack_facts([], out, "gitlab")


def test_no_named_app_no_attack_receipts():
    assert _derive_attack_facts(["searchsploit gitlab"], "", "") == []
    # compound capability-probe segments must not fabricate attacks either
    cmd = ("id; sudo -n true 2>&1; command -v searchsploit msfconsole; "
           "echo done; curl -s http://198.51.100.10/ | head -5")
    assert _derive_attack_facts([cmd], "", "gitlab") == []


def test_doc_read_is_not_an_attack_chain_but_lookup_counts():
    # reading a writeup is research (cve-lookup), NOT known-exploit-chain
    facts = _derive_attack_facts(["searchsploit -x 49979", "cat /usr/share/exploitdb/49979.txt"], "", "gitlab")
    assert "attack=gitlab:cve-lookup" in facts
    assert "attack=gitlab:known-exploit-chain" not in facts
    # msfconsole WITHOUT run/exploit is not an attack chain
    facts = _derive_attack_facts(["msfconsole -q -x 'search gitlab; show options; exit'"], "", "gitlab")
    assert "attack=gitlab:known-exploit-chain" not in facts


def test_self_reported_attack_facts_are_stripped():
    kept = _strip_derived(["flag=HTB{x}", "attack=gitlab:cve-lookup", "app=gitlab:10.0.0.1"])
    assert kept == ["flag=HTB{x}", "app=gitlab:10.0.0.1"]
    assert _strip_derived(None) == []


def test_ip_shaped_app_version_is_blanked():
    # run 746 step 1: app=drupal:198.51.100.10 facts made the Ariadne parser read the IP
    # as the version -> searchsploit hint polluted. The fold sink must blank IP versions.
    c = _cartographer(_mk_doc())
    c.fold(["app=drupal:198.51.100.10", "app=osticket:198.51.100"], ts=1)
    n = c.doc["nodes"]["app:drupal"]
    assert n["meta"]["version"] == ""
    assert n["meta"]["app"] == "drupal"
    assert c.doc["nodes"]["app:osticket"]["meta"]["version"] == ""


def test_salvage_app_fact_has_no_ip_suffix():
    from trooper import _salvage_facts
    out = ["$ curl -s http://198.51.100.10:8080/\npowered by osTicket 1.14"]
    facts = _salvage_facts(out, "198.51.100.10")
    assert "app=osticket" in facts
    assert not any(f.startswith("app=osticket:") for f in facts)


def test_prime_chunk_reaches_transcript_for_attack_receipt():
    # the deterministic searchsploit prime (lane _app) must land in the returned
    # transcript with the auto-searchsploit label — run 748 step 3: the prime ran but
    # the chunk never reached res['output'], so attack=gitlab:cve-lookup never folded
    import trooper as TR
    real_run, real_chat = TR.run_cmd, TR._chat
    try:
        TR.run_cmd = lambda cmd, target: (
            "Exploit: GitLab 13.10 RCE | ruby/webapps/49979.py"
            if "searchsploit" in cmd else "(no output)")
        TR._chat = lambda msgs, key: ('VERDICT: {"success": true, "evidence": "done", '
                                      '"facts": [], "telemetry": {"observed": "gitlab", '
                                      '"tried": "", "blocked": "", "next": ""}}')
        v = TR.Trooper().fire({"id": "t", "target": "198.51.100.10",
                               "objective": "exploit the gitlab", "_app": "gitlab"})
    finally:
        TR.run_cmd, TR._chat = real_run, real_chat
    assert "[auto-searchsploit gitlab]" in (v["output"] or "").lower()
    assert "attack=gitlab:cve-lookup" in _derive_attack_facts([], v["output"], "gitlab")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
