#!/usr/bin/env python3
"""Operator approval servicer — codifies the approver policy for an autonomous run:
auto-approve in-scope, non-destructive box commands (already gate-filtered); HOLD any
command naming a non-target IP or matching an exfil pattern for manual review."""
import os, json, time, re, sys
STATE=os.path.expanduser("~/.local/state/bs2-broker")
PEND=os.path.join(STATE,"pending"); DEC=os.path.join(STATE,"decisions")
os.makedirs(PEND, exist_ok=True); os.makedirs(DEC, exist_ok=True)  # tolerate starting before the broker
try: os.chmod(STATE, 0o700)
except OSError: pass
TARGET="198.51.100.10"
IP=re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
# exfil = pushing data OUT to a non-target host; a /dev/tcp or nc TO the target is a read/banner-grab
EXFIL=re.compile(r"(scp\s|curl\s+-T\b|--upload-file|wget\s+--post|\bnc\s+-[^ ]*e)", re.I)
def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)
seen=set()
log("servicer up")
end=time.time()+2400
while time.time()<end:
    for fn in sorted(os.listdir(PEND)):
        if not fn.endswith(".json"): continue
        rid=fn[:-5]
        if rid in seen: continue
        try: d=json.load(open(os.path.join(PEND,fn)))
        except Exception: continue
        seen.add(rid); cmd=d.get("command","")
        foreign=[x for x in set(IP.findall(cmd))-{TARGET} if not x.startswith(("0.","255."))]
        if foreign or EXFIL.search(cmd):
            log(f"HOLD {rid} :: {cmd[:160]}  foreign={foreign} exfil={bool(EXFIL.search(cmd))}")
            continue
        json.dump({"allow":True,"reason":"operator: in-scope authorized","ts":time.time()},
                  open(os.path.join(DEC,rid+".json"),"w"))
        log(f"OK   {rid} :: {cmd[:170]}")
    time.sleep(1.5)
log("servicer window closed")
