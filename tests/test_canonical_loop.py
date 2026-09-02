"""Canonical Battlestation loop fixes — the 2026-08-25 build batch:

1. Battle Charter artifact (charter.py): loads, binds the target, GATES run start on a
   target match, renders into the manager picture.
2. Hands owns routine recon (hands.py): recon_sweep + verify_vhosts with injectable
   runners; gnmap parsers live with hands. run_htb delegates, never inlines.
3. Catalog is a LIBRARY (recipes.available_for): pure index — fires nothing, decides
   nothing; no hidden keyword auto-fire (fire_command has no recipe path left).
4. BS2 governs execution (target_exec.classify_action): trooper + recipes route their
   capability class through the §10.1 door; AUTOTURRET is a manager verb, not an auto.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))
sys.path.insert(0, os.path.join(HERE, "..", "manager"))

import charter                                            # noqa: E402
import hands                                              # noqa: E402
import recipes                                            # noqa: E402
from target_exec import classify_action                   # noqa: E402


# ---------- 1. Battle Charter ----------

def test_charter_default_loads_and_binds():
    c, src = charter.load()
    assert src == "default"
    charter.bind_target(c, "198.51.100.10")
    ok, why = charter.validate_target(c, "198.51.100.10")
    assert ok and not why


def test_charter_gates_wrong_target():
    c, _ = charter.load()
    charter.bind_target(c, "198.51.100.10")
    # validate a DIFFERENT host than the one bound — that is the out-of-scope case this gates
    ok, why = charter.validate_target(c, "203.0.113.99")
    assert not ok and "not in charter scope" in why


def test_charter_file_override():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"title": "custom", "scope": {"hosts": ["1.2.3.4"], "cidrs": [],
                    "excluded_cidrs": []}, "actions": {}, "stop_conditions": []}, fh)
        path = fh.name
    try:
        c, src = charter.load(path)
        assert src == path and c["title"] == "custom"
        charter.bind_target(c, "1.2.3.4")
        ok, _ = charter.validate_target(c, "1.2.3.4")
        assert ok
    finally:
        os.unlink(path)


def test_charter_render_mentions_target():
    c, _ = charter.load()
    charter.bind_target(c, "198.51.100.10")
    assert "198.51.100.10" in charter.render(c)
    assert "BATTLE CHARTER" in charter.render(c)


# ---------- 2. Hands owns routine recon ----------

def test_gnmap_ports():
    gnmap = ("# Nmap 7.94 scan\n"
             "Host: 10.0.0.1 ()\tStatus: Up\n"
             "Host: 10.0.0.1 ()\tPorts: 21/open/tcp//ftp//vsftpd 3.0.3/, 22/open/tcp//ssh//, 80/closed/tcp//http///\n")
    assert hands.gnmap_ports(gnmap) == [21, 22]


def test_gnmap_surface_versions():
    gnmap = ("Host: 10.0.0.1 ()\tPorts: 21/open/tcp//ftp//vsftpd 3.0.3/, "
             "80/open/tcp//http//Apache httpd 2.4.41 ((Ubuntu))/\n")
    surf = hands.gnmap_surface(gnmap, "10.0.0.1")
    ports = {p["port"]: p for p in surf["hosts"][0]["ports"]}
    assert ports[21]["name"] == "ftp" and ports[21]["version"] == "3.0.3"
    assert ports[80]["name"] == "http" and "Apache" in ports[80]["product"]
    assert ports[80]["version"] == "2.4.41"


def test_verify_vhosts_ghost_and_real():
    """Same size+hash -> ghost; different body -> real; failed fetch -> unverifiable."""
    calls = []
    def runner(cmd, t):
        calls.append(cmd)
        if "md5sum" in cmd and "Host:" in cmd:
            name = cmd.split("Host: ")[1].split("'")[0]
            if name == "ghost.example":
                return "1000\nd41d8cd98f00b204e9800998ecf8427e  x\n"
            if name == "real.example":
                return "5000\nffffffffffffffffffffffffffffffff  x\n"
            return "(timeout)"
        return "1000\nd41d8cd98f00b204e9800998ecf8427e  base\n"
    records = []
    dead, verified = hands.verify_vhosts(
        "10.0.0.1", ["ghost.example", "real.example", "flaky.example"], runner,
        records=records)
    assert dead == ["ghost.example"]
    assert verified == ["real.example"]
    assert len(records) == 2 and all(not record.validate() for record in records)


def test_recon_sweep_with_fake_runner():
    def runner(cmd, t):
        if "-sV" in cmd:
            return ("Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.2p1/, "
                    "80/open/tcp//http//nginx/\n")
        return "Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\n"
    records = []
    surf = hands.recon_sweep("10.0.0.1", runner, budget=480, records=records)
    assert surf is not None
    assert [p["port"] for p in surf["hosts"][0]["ports"]] == [22, 80]
    assert [record.kind for record in records] == ["port", "port"]
    assert all(not record.validate() for record in records)


def test_cartographer_fold_record_matches_legacy_string():
    from recon_record import ReconObservation
    from cartographer.core import Cartographer
    import tempfile

    left, right = Cartographer(tempfile.mkdtemp()), Cartographer(tempfile.mkdtemp())
    for cart in (left, right):
        cart.doc["target"] = "example.test"
        cart._node("host:example.test", "host", "example.test", ts=1)
    legacy = "vhost=portal.example.test"
    record = ReconObservation(
        target="example.test", ts=2, node_id="vhost:portal.example.test", kind="vhost",
        data={"fold": legacy}, evidence=["fixture:1"], producer="test")
    assert left.fold([legacy], ts=2) == right.fold(record, ts=2)
    assert left.doc == right.doc


def test_hands_runner_called_with_two_positional_args():
    """REGRESSION (run 750 ritual returned ports=0 seconds=0): hands must call runner as
    runner(cmd, timeout) — TEXEC.run accepts only (cmd, target) positionally, so a
    3-positional-arg call is an instant TypeError swallowed by the fail-soft path."""
    shapes = []
    def runner(*args):
        shapes.append(len(args))
        return ""
    hands.recon_sweep("10.0.0.1", runner, budget=5)
    assert shapes and all(n == 2 for n in shapes)
    shapes2 = []
    def runner2(*args):
        shapes2.append(len(args))
        return "1\nd41d8cd98f00b204e9800998ecf8427e  x\n"
    hands.verify_vhosts("10.0.0.1", ["a.example"], runner2)
    assert shapes2 and all(n == 2 for n in shapes2)


# ---------- 3. Catalog is a library, not a decider ----------

def test_available_for_matches_ports():
    lanes = recipes.available_for([21, 80])
    assert "ftp-anon" in lanes and "web-enum" in lanes
    assert "dns-axfr" not in lanes and "smb-null" not in lanes


def test_available_for_empty():
    assert recipes.available_for([]) == []
    assert recipes.available_for(None) == []


def test_available_for_cheap_only_index_fires_nothing():
    """The index must never execute anything — no recipe engine construction, no sh()."""
    lanes = recipes.available_for([21, 53, 139, 80])
    assert sorted(lanes) == sorted(["ftp-anon", "dns-axfr", "smb-null", "web-enum"])


def test_fire_command_has_no_recipe_autofire():
    """The hidden keyword auto-fire is GONE from fire_command (canonical 2026-08-25):
    no GB_RECIPE_FIRST branch, no _lanes_for call left in the TASK path."""
    import run_htb
    src = open(run_htb.__file__).read()
    import re as _re
    body = src[_re.search(r"def fire_command", src).start():
               _re.search(r"def ariadne_routes", src).start()]
    assert "GB_RECIPE_FIRST" not in body
    assert "_lanes_for(" not in body
    assert "eng.fire" not in body


def test_autoturret_offers_index_only():
    import run_htb
    from types import SimpleNamespace
    doc = {"nodes": {"port:21": {"kind": "port", "meta": {"port": 21}},
                     "port:80": {"kind": "port", "meta": {"port": 80}}}}
    offers = run_htb._autoturret_offers(SimpleNamespace(doc=doc))
    assert "ftp-anon" in offers and "web-enum" in offers
    assert "dns-axfr" not in offers
    assert run_htb._autoturret_offers(SimpleNamespace(doc={"nodes": {}})) == []


def test_run_identity_names_runs_by_charter_ports():
    """Concurrent runs against the SAME host (local lab apps share 127.0.0.1) must
    never share state: charter scope.ports names the run (lab pass 1 collision)."""
    import run_htb
    ts = 12345
    assert run_htb._run_identity("127.0.0.1", {"scope": {"ports": [3006]}}, ts) \
        == "127-0-0-1-p3006-12345"
    assert run_htb._run_identity("127.0.0.1", {"scope": {"ports": [8888]}}, ts) \
        == "127-0-0-1-p8888-12345"
    assert run_htb._run_identity("10.0.0.1", {"scope": {}}, ts) == "10-0-0-1-12345"
    assert run_htb._run_identity("10.0.0.1", None, ts) == "10-0-0-1-12345"


def test_governed_info_reads_seam_caps():
    import run_htb
    seam_dir = tempfile.mkdtemp()
    assert run_htb._governed_info("") is None
    assert run_htb._governed_info(seam_dir) is None          # no seam.json yet
    with open(f"{seam_dir}/seam.json", "w") as fh:
        json.dump({"caps": {"web.recon": "c1", "net.recon": "c2"}}, fh)
    info = run_htb._governed_info(seam_dir)
    assert info == {"caps": ["net.recon", "web.recon"], "witnessed": False}
    with open(f"{seam_dir}/seam.json", "w") as fh:
        json.dump({"caps": {"web.recon": "c1", "web.exploit": "c2"}}, fh)
    assert run_htb._governed_info(seam_dir)["witnessed"] is True


def test_build_prompt_governed_block():
    from run_htb import build_prompt
    p = build_prompt("127.0.0.1", [], [], [], None, None, governed={
        "caps": ["net.recon", "web.recon"], "witnessed": False})
    assert "GOVERNED EXECUTION" in p and "RECON-ONLY" in p
    p2 = build_prompt("127.0.0.1", [], [], [], None, None, governed={
        "caps": ["web.exploit"], "witnessed": True})
    assert "witnessed seam" in p2
    p3 = build_prompt("127.0.0.1", [], [], [], None, None)
    assert "GOVERNED EXECUTION" not in p3


def test_recon_sweep_charter_scoped_ports():
    """Charter-scoped ports (local lab apps on a shared host): discovery is SKIPPED —
    hands version-scans exactly the declared ports, never a -p- sweep of localhost."""
    calls = []
    def runner(cmd, t):
        calls.append(cmd)
        return "\n"                      # empty output: gnmap_ports finds nothing
    out = hands.recon_sweep("127.0.0.1", runner, budget=60, ports=[3006, 8888])
    # surface still falls back to the declared ports when the vscan returns nothing
    assert [p["port"] for p in out["hosts"][0]["ports"]] == [3006, 8888]
    assert len(calls) == 2               # one version scan + one cleanup, nothing else
    assert "-sV" in calls[0] and "-p 3006,8888" in calls[0]
    assert "-p-" not in calls[0]


def test_manager_picture_redispatches_on_new_surface():
    """pack->author->execute->ADAPT (2026-08-25): a surface folded MID-RUN must be in
    the manager's NEXT picture. The loop recomputes frontier/coverage from the live map
    every step and untouched nodes rank highest — pin it so the adapt step can never be
    regressed into a one-shot objective."""
    import tempfile
    from cartographer.core import Cartographer
    import run_htb
    cart = Cartographer(tempfile.mkdtemp())
    cart._node("host:127.0.0.1", "host", "127.0.0.1", ts=1)
    cart.fold(["port=3006"], ts=1)
    # the live fold vocabulary: a web surface arrives as web<port>=<handle>
    cart.fold(["web3006=/api/secret-admin"], ts=2)          # folded mid-run
    fr = cart.frontier(top=8)
    new_edge = [r for r in fr if "http_3006" in f"{r['id']} {r['label']}"]
    assert new_edge and new_edge[0]["state"] == "untouched"
    prompt = run_htb.build_prompt("127.0.0.1", [], [], [], [], [], frontier=fr)
    assert "http_3006" in prompt                          # the manager SEES it next step
    # once the edge is closed it leaves the frontier
    cart.doc["nodes"][new_edge[0]["id"]]["state"] = "exhausted"
    assert new_edge[0]["id"] not in [r["id"] for r in cart.frontier(top=8)]


def test_parse_action_autoturret():
    from run_htb import parse_action
    assert parse_action("AUTOTURRET")[0] == "AUTOTURRET"
    assert parse_action("WHY: cheap lanes first\nAUTOTURRET")[0] == "AUTOTURRET"
    assert parse_action("TASK enumerate the web app")[0] == "TASK"


# ---------- loopback carve-out is read at FIRE time (lab passes 2-3 wall) ----------

def test_loopback_carveout_fire_time_and_target_gated(monkeypatch):
    import trooper
    cmd = "curl -s http://127.0.0.1:3006/api/products"
    monkeypatch.delenv("GB_ALLOW_LOOPBACK", raising=False)
    # run_deep_deepseek sets both flags at IMPORT time (imported elsewhere in the suite);
    # this test must own them like the trooper reads them — at fire time
    monkeypatch.delenv("GB_CHARTER_PORTS", raising=False)
    assert trooper.scope_ok(cmd, "127.0.0.1")[0] is False     # default: hard deny
    monkeypatch.setenv("GB_ALLOW_LOOPBACK", "1")
    assert trooper.scope_ok(cmd, "127.0.0.1")[0] is True      # charter-scoped lab target
    # the carve-out is TARGET-gated: an HTB target keeps the deny even with the flag
    assert trooper.scope_ok(cmd, "198.51.100.10")[0] is False
    monkeypatch.setenv("GB_ALLOW_LOOPBACK", "0")
    assert trooper.scope_ok(cmd, "127.0.0.1")[0] is False     # flag off again -> denied


def test_charter_ports_restrict_loopback_trooper(monkeypatch):
    """Pass-4 lesson 2026-08-25: the loopback carve-out opens the HOST; the charter's
    declared ports must keep the trooper path inside them (hands already honors charter
    ports for its own sweeps — a manager-authored sweep folded ports 1/2/999 past :3006)."""
    import trooper
    monkeypatch.setenv("GB_ALLOW_LOOPBACK", "1")
    monkeypatch.setenv("GB_CHARTER_PORTS", "3006")
    # the declared port passes
    assert trooper.scope_ok("curl -s http://127.0.0.1:3006/api/products",
                            "127.0.0.1")[0] is True
    # an out-of-charter port reference is denied with a naming reason
    ok, why = trooper.scope_ok("curl -s http://127.0.0.1:8888/x", "127.0.0.1")
    assert not ok and "8888" in why and "charter" in why
    # a full-port sweep is denied outright
    ok, why = trooper.scope_ok("nmap -p- 127.0.0.1", "127.0.0.1")
    assert not ok and "full-port sweep" in why
    ok, why = trooper.scope_ok("nmap -p 22,80 127.0.0.1", "127.0.0.1")
    assert not ok and "22" in why
    # a portless local command still passes (the rule closes the port axis only)
    assert trooper.scope_ok("curl -s 127.0.0.1", "127.0.0.1")[0] is True
    # no charter -> no port restriction (backward compatible)
    monkeypatch.delenv("GB_CHARTER_PORTS")
    assert trooper.scope_ok("curl -s http://127.0.0.1:8888/x", "127.0.0.1")[0] is True
    # charter ports only apply on the loopback carve-out; the hard deny stands elsewhere
    monkeypatch.setenv("GB_CHARTER_PORTS", "3006")
    assert trooper.scope_ok("curl -s http://127.0.0.1:3006/x", "198.51.100.10")[0] is False


# ---------- 4. BS2 evaluates (classify_action) ----------

def test_classify_action_recon_vs_exploit():
    assert classify_action("nmap -sV 10.0.0.1") == "web.recon"
    assert classify_action("gobuster dir -u http://10.0.0.1 -w c.txt") == "web.recon"
    assert classify_action("curl -s http://10.0.0.1/") == "web.recon"
    assert classify_action("searchsploit gitlab 13.10") == "web.recon"
    assert classify_action("sqlmap -u http://10.0.0.1/?id=1 --dump") == "web.exploit"
    assert classify_action("hydra -l admin -P w.txt 10.0.0.1 ssh") == "web.exploit"
    assert classify_action("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'") == "web.exploit"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
