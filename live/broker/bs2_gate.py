#!/usr/bin/env python3
"""bs2-gate — the INTERACTIVE operator gate for the BS2 backend.

Run this in your terminal during an engagement. It watches the governed door's
approval queue and, for EVERY command that would touch a target, shows you the
exact command + context and blocks until YOU decide. Nothing reaches the box
until you press a key. This is the human-in-the-loop surface the harness is
built around (the auto-servicer is only for unattended/CI runs).

Keys per prompt:
  y / enter  approve this one command
  n          deny this one command
  a          approve every command for the rest of this session (unattended)
  s          approve all queued RIGHT NOW, then keep prompting for new ones
  q          deny this one and quit the gate (remaining commands fail closed)
"""
import os, sys, json, time, select, termios, tty
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bs2.approval import write_decision

STATE = os.environ.get("BS2_BROKER_STATE", os.path.expanduser("~/.local/state/bs2-broker"))
PEND = os.path.join(STATE, "pending"); DEC = os.path.join(STATE, "decisions")

C = dict(rst="\033[0m", b="\033[1m", ylw="\033[1;33m", grn="\033[1;32m",
         red="\033[1;31m", dim="\033[2m", cyn="\033[36m")

def _decide(rid, allow, reason=""):
    write_decision(STATE, rid, allow, reason)

def _pending():
    if not os.path.isdir(PEND): return []
    rows = []
    for fn in sorted(os.listdir(PEND)):
        if fn.endswith(".json"):
            try: rows.append(json.load(open(os.path.join(PEND, fn))))
            except Exception: pass
    return sorted(rows, key=lambda r: r.get("ts", 0))

def _getkey():
    fd = sys.stdin.fileno(); old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            if select.select([sys.stdin], [], [], 0.3)[0]:
                return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _show(r, n, approved, denied):
    ips = ",".join(r.get("resolved_ips") or []) or "-"
    print(f"\n{C['ylw']}┌─ APPROVAL #{n}  (approved:{approved} denied:{denied}) ───────────────────────────{C['rst']}")
    print(f"{C['b']}│ class :{C['rst']} {r.get('action_class')}")
    print(f"{C['b']}│ target:{C['rst']} {r.get('target')}  {C['dim']}[{ips}]{C['rst']}")
    run = r.get('run_id',''); ass = r.get('assessment_id','')
    if run and run != 'unbound': print(f"{C['dim']}│ run   : {run}  assess: {ass}{C['rst']}")
    print(f"{C['b']}│ command:{C['rst']}")
    cmd = r.get("command","")
    for line in (cmd[i:i+100] for i in range(0, len(cmd), 100)):
        print(f"{C['cyn']}│   {line}{C['rst']}")
    print(f"{C['ylw']}└─ [{C['grn']}y{C['ylw']}]approve [{C['red']}n{C['ylw']}]deny [a]ll [s]ync-drain [q]uit{C['rst']} ", end="", flush=True)

def main():
    if not sys.stdin.isatty():
        print("bs2-gate needs an interactive terminal (use bs2-approve for scripted decisions).")
        return 2
    os.makedirs(PEND, exist_ok=True); os.makedirs(DEC, exist_ok=True)
    print(f"{C['grn']}bs2-gate up{C['rst']} — watching {PEND}\n"
          f"{C['dim']}every command below touches the target and waits for YOUR key.{C['rst']}")
    seen = set(); n = 0; approved = 0; denied = 0; auto = False
    while True:
        for r in _pending():
            rid = r["id"]
            if rid in seen: continue
            seen.add(rid); n += 1
            if auto:
                _decide(rid, True, "operator: session auto-approve"); approved += 1
                print(f"{C['grn']}✔ auto{C['rst']} {r.get('command','')[:90]}")
                continue
            _show(r, n, approved, denied)
            k = _getkey().lower()
            print(k if k.strip() else "↵")
            if k in ("y", "\r", "\n", " "):
                _decide(rid, True, "operator: approved"); approved += 1
                print(f"{C['grn']}  ✔ approved{C['rst']}")
            elif k == "n":
                _decide(rid, False, "operator: denied"); denied += 1
                print(f"{C['red']}  ✗ denied{C['rst']}")
            elif k == "a":
                auto = True; _decide(rid, True, "operator: approved (all)"); approved += 1
                print(f"{C['ylw']}  ⇒ approving all remaining this session{C['rst']}")
            elif k == "s":
                for rr in _pending():
                    if rr["id"] not in seen or rr["id"] == rid:
                        seen.add(rr["id"]); _decide(rr["id"], True, "operator: drained"); approved += 1
                print(f"{C['ylw']}  ⇒ drained the current queue{C['rst']}")
            elif k == "q":
                _decide(rid, False, "operator: quit"); denied += 1
                print(f"{C['red']}  ✗ denied; gate closing — remaining commands fail closed{C['rst']}")
                return 0
        time.sleep(0.3)

if __name__ == "__main__":
    sys.exit(main())
