#!/usr/bin/env python3
"""OFFLINE self-test for the closer's grounded proof-gate + needs-enforcement.

No network, no target, no LLM — it scripts a fake trooper (honest AND hallucinating) and a
fake recipe layer (no primitive ever lands, forcing the iterate path), then asserts the gate:
  1. DROPS a compromise-grade fact the trooper merely ASSERTED with no backing output
     (the 2026-08-22 .205 failure: cred=root:... with zero command output was believed).
  2. ACCEPTS the same class of fact when its value is present in real captured output.
  3. TRUSTS deterministic primitive facts (ground=False path) unchanged.
  4. ENFORCES needs: a rung whose prerequisite fact is missing is skipped, never iterated,
     so a STUCK foothold can never let loot/own-dc fabricate a downstream win.
  5. End-to-end: an all-hallucination trooper yields success=false / dc_owned=false — no
     fabricated ownership.

Run:  GB_KNOWLEDGE=0 python3 closer_selftest.py     (exit 0 = all pass)
"""
import os, sys
os.environ.setdefault("GB_KNOWLEDGE", "0")          # skip corpus greps in _ideas
import closer as C

FAILS = []
def check(name, cond):
    print(("  PASS  " if cond else "  FAIL  ") + name)
    if not cond:
        FAILS.append(name)


class FakeRx:
    """No primitive ever lands -> every rung falls through to the iterate path."""
    def __init__(self, *a, **k): self.bind = {}
    def fire(self, lane): return None
    def discover(self): pass


class FakeTrooper:
    def __init__(self, script): self.script = script
    def fire(self, lane):
        return self.script.get(lane.get("id"),
                               {"success": False, "evidence": "turn cap", "facts": [],
                                "output": "", "cmds": []})


def new_closer(script=None):
    c = C.Closer("10.10.10.10", log=lambda m: None)   # silent
    c.rx = FakeRx()
    c.tr = FakeTrooper(script or {})
    c._junk = set()                                   # skip whoami on jump host
    c._escalate = lambda *a, **k: False               # never ping-ben / write mailbox in a test
    return c


# ---- 1. unit: _grounded -------------------------------------------------------------------
print("[unit] _grounded — a fact counts only if the output backs it")
c = new_closer()
check("shell dropped without a uid= token",      c._grounded("shell=www-data", "") is False)
check("shell accepted with uid= token",          c._grounded("shell=www-data", "uid=33(www-data) gid=33") is True)
check("cred dropped when secret absent from out", c._grounded("cred=root:Sup3RS3cuR3@123", "") is False)
check("cred accepted when secret in output",     c._grounded("cred=root:hunter2", "cat wp-config: DB_PASSWORD=hunter2") is True)
check("dc_cred dropped when unbacked",           c._grounded("dc_cred=administrator:Passw0rd1!", "login failed") is False)
check("hash dropped when unbacked",              c._grounded("hash=$P$Babc123", "") is False)
check("hash accepted when in output",            c._grounded("hash=$P$Babc123", "user | $P$Babc123") is True)
check("flag not grounding-gated here (oracle's job)", c._grounded("flag=HTB{x}", "") is True)

# ---- 2. unit: _add ground vs trust --------------------------------------------------------
print("[unit] _add — ground=True gates trooper facts; ground=False trusts primitives")
c = new_closer()
c._add(["cred=root:FAKE"], evidence="", ground=True)
check("ungrounded trooper cred is NOT added",    "cred=root:FAKE" not in c.facts)
c._add(["cred=root:REAL"], evidence="creds file: root:REAL", ground=True)
check("grounded trooper cred IS added",          "cred=root:REAL" in c.facts)
c._add(["cred=svc:TRUSTED"], ground=False)       # primitive path
check("primitive cred trusted without evidence", "cred=svc:TRUSTED" in c.facts)

# ---- 3. unit: _have (needs satisfaction) --------------------------------------------------
print("[unit] _have — prerequisite key satisfied by a typed fact")
c = new_closer(); c.facts = ["shell=www-data"]
check("_have('shell') true from shell=www-data", c._have("shell") is True)
check("_have('cred') false when absent",         c._have("cred") is False)

# ---- 4. integration: all-hallucination trooper CANNOT fabricate ownership -----------------
print("[integration] foothold asserts a shell with NO uid output -> STUCK -> nothing downstream")
script = {
    # foothold: claims a shell but the 'output' has no uid= token -> must be dropped
    "foothold": {"success": True, "evidence": "got shell (lie)", "facts": ["shell=www-data"],
                 "output": "i ran some stuff and i think i have a shell", "cmds": ["curl x"]},
    # own-dc: would claim a DC cred with no backing -> must be dropped if ever reached
    "own-dc":   {"success": True, "evidence": "owned dc (lie)", "facts": ["dc_cred=administrator:Passw0rd1!"],
                 "output": "spray done", "cmds": ["rpcclient x"]},
    "crack":    {"success": True, "evidence": "cracked (lie)", "facts": ["cred=root:Sup3RS3cuR3@123"],
                 "output": "hashcat ran", "cmds": ["hashcat x"]},
}
c = new_closer(script)
res = c.run()
check("no shell fact survived (ungrounded)",     not any(f.startswith("shell=") for f in c.facts))
check("no cred fact fabricated",                 not any(f.startswith("cred=") for f in c.facts))
check("no dc_cred fabricated",                   not any(f.startswith("dc_cred=") for f in c.facts))
check("result NOT dc_owned",                     res["dc_owned"] is False)
check("result NOT rooted",                       res["rooted"] is False)
check("no flags fabricated",                     res["flags"] == [])

# ---- 5. integration: a GROUNDED foothold advances, but DC is not fabricated ----------------
print("[integration] grounded foothold is accepted; DC still honestly not owned (no cred)")
script2 = {
    "foothold": {"success": True, "evidence": "shell", "facts": ["shell=www-data"],
                 "output": "$ id\nuid=33(www-data) gid=33(www-data)", "cmds": ["lfi->rce id"]},
}
c = new_closer(script2)
res2 = c.run()
check("grounded shell WAS accepted",             "shell=www-data" in c.facts)
check("DC honestly not owned (no real cred)",    res2["dc_owned"] is False)

print()
if FAILS:
    print(f"SELFTEST FAILED: {len(FAILS)} check(s) -> {FAILS}"); sys.exit(1)
print("SELFTEST PASSED: grounded proof-gate + needs-enforcement hold; no fabricated ownership.")
