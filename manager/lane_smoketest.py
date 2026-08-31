#!/usr/bin/env python3
"""Live single-lane validation of the north-star manager-in-the-loop. Imports the real driver,
provisions real crAPI test accounts, feeds real Ariadne goals + Memoria, runs ONE bac lane with
the REAL Opus brain (claude -p) authoring and REAL DeepSeek troopers firing. Bounded step_cap."""
import os, sys, json, time
os.environ.setdefault("ITER_CAP","1")
sys.path.insert(0,"/opt/bs2/manager")
import run_deep_deepseek as RD   # sets env, imports trooper(deepseek), manager_loop, memoria
import manager_bridge as MB

RUN_DIR = RD.RUN_DIR
os.makedirs(RUN_DIR, exist_ok=True)
import shutil
for f in ("worklist.json","ariadne_facts.jsonl"):
    shutil.copy(f"{RD.SRC}/{f}", f"{RUN_DIR}/{f}")
json.dump({"target":RD.TARGET,"proven":[],"apps":{"crapi":RD.TARGET},"negatives":[]},
          open(f"{RUN_DIR}/recon.json","w"))

print(">> provisioning two crAPI test accounts ...", flush=True)
pairs = RD.provision_tokens()
tokens=[p[0] for p in pairs]; emails=[p[1] for p in pairs]
print(f">> provisioned {len(tokens)} accounts", flush=True)
assert tokens, "no tokens provisioned"

adv = MB.build_advisory(RUN_DIR, posture="measured")
goals = adv.get("goals", [])
print(f">> ariadne goals: {len(goals)} | " + " ".join("{}:{}".format(g.get('goal'), g.get('status')) for g in goals[:6]), flush=True)

wl = json.load(open(f"{RUN_DIR}/worklist.json"))
cls = "broken-access-control"
cls_rows = [r for r in wl if r.get("class")==cls]
endpoints = [r["endpoint"] for r in cls_rows]
print(f">> lane class={cls} endpoints={endpoints}", flush=True)

mem_hint = ""
try:
    if RD.MEM: mem_hint = RD.MEM.hints_for(cls, cls_rows, RD.TARGET, k=3, timeout=7) or ""
except Exception as e:
    print(">> memoria soft-fail:", e)
print(f">> memoria hint chars: {len(mem_hint)}", flush=True)

def note(m): print(f"   [note] {m}", flush=True)

# bound the test: smaller step cap than production
import manager_loop as ML
t0=time.time()
tok = tokens[0]; my_email = emails[0]
fire = {"probe": lambda c: RD._fire_probe(RD._ensure_status_capture(c)),
        "listids": lambda c: RD._fire_listids(c),
        "ownerdiff": lambda u: RD._verify_owner_diff(u, tok, my_email)}
res = ML.run_manager_lane(cls, endpoints, cls_rows, tokens, emails, goals, mem_hint,
                          fire, note, step_cap=8)
print(f"\n>> LANE DONE in {int(time.time()-t0)}s", flush=True)
print(json.dumps({k:v for k,v in res.items()}, indent=1))
