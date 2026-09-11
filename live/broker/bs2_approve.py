#!/usr/bin/env python3
"""bs2-approve — operator CLI decision surface for the BS2 backend gate.

  bs2-approve list                 # pending box-touching actions
  bs2-approve show <id>            # full command + context
  bs2-approve allow <id>
  bs2-approve deny  <id> [reason]
"""
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bs2.approval import write_decision
STATE = os.environ.get("BS2_BROKER_STATE", os.path.expanduser("~/.local/state/bs2-broker"))
PENDING = os.path.join(STATE, "pending"); DECIDED = os.path.join(STATE, "decisions")

def _pend():
    if not os.path.isdir(PENDING): return []
    out = []
    for fn in sorted(os.listdir(PENDING)):
        if fn.endswith(".json"):
            with open(os.path.join(PENDING, fn)) as f: out.append(json.load(f))
    return sorted(out, key=lambda r: r.get("ts", 0))

def _decide(rid, allow, reason=""):
    write_decision(STATE, rid, allow, reason)
    print(("ALLOWED " if allow else "DENIED  ") + rid + ((" — " + reason) if reason else ""))

def main():
    a = sys.argv[1:]
    if not a or a[0] == "list":
        rows = _pend()
        if not rows: print("(no pending approvals)"); return
        for r in rows:
            ips = ",".join(r.get("resolved_ips") or []) or "-"
            print(f"{r['id']}  {r.get('action_class'):<16} {r.get('target')}  [{ips}]")
            print(f"    $ {r.get('command')}")
        return
    cmd = a[0]
    if cmd == "show":
        for r in _pend():
            if r["id"] == a[1]: print(json.dumps(r, indent=2)); return
        print("no such pending id"); return
    if cmd == "allow": _decide(a[1], True); return
    if cmd == "deny":  _decide(a[1], False, " ".join(a[2:]) or "operator_denied"); return
    print(__doc__)

if __name__ == "__main__":
    main()
