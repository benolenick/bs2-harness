#!/usr/bin/env python3
"""
Faithful HEADLESS port of the other agent's autocannon (warroom.py @ autocannon-claude-v1).

Runs their ACTUAL logic — their build_belt(), recon (nmap discovery), rce/ask_17b, lane
hit-predicates, hardcoded cred spray, and dataflow scheduler semantics (CAP=20 concurrent,
fire when needs⊆facts, reschedule on confirmed `gives`, amber→your-host-1.7b judge) — with the
tkinter war-room stripped so it can be timed and scored head-to-head with carousel.py.

Deployment mirrors theirs exactly: orchestrate on your-host, ssh-mux fire to your-host (which reaches
the docker nets), gate ambiguous hits via your-host qwen3:1.7b.  DC lanes fire smbclient
DIRECTLY (their design — no pivot; relies on the your-host host routing to the internal /24).

Emits result.json in the SAME schema as carousel.py so the harness can compare apples to apples.
"""
import asyncio, json, os, re, time, sys, types

EDGE = os.environ.get("GB_EDGE", "172.32.0")   # default lab2 (their default)
INT  = os.environ.get("GB_INT",  "172.33.0")
WORK = os.environ.get("GB_WORK", "/tmp/gb-ab/theirs")
os.makedirs(WORK, exist_ok=True)

# import their real logic without launching Tk (stub tkinter + submodules)
from unittest.mock import MagicMock
for _m in ("tkinter", "tkinter.font", "tkinter.ttk"):
    sys.modules[_m] = MagicMock()
sys.path.insert(0, "/opt/bs2/live")
sys.path.insert(0, "/opt/bs2/catalog")
os.environ.setdefault("GB_EDGE", EDGE); os.environ.setdefault("GB_INT", INT)
import warroom as W          # noqa: their module; EDGE/INT read from env at its import

JAGG = W.JAGG
CTRL = W.CTRL
CAP  = W.CAP
build_belt = W.build_belt
ask_17b    = W.ask_17b

T0 = time.monotonic()
def now(): return time.monotonic() - T0
FLAG_RE = re.compile(r"FLAG\{[^}\s\"']+\}")

class S:
    facts=set(); flags={}; shots=0; log=[]; dc=None; inflight=0; maxc=0; dc_cred=None
    creds_source="hardcoded (answer-key: tom:charlie1, administrator:Passw0rd1! baked into belt)"

def ev(kind,lane,detail,verdict):
    d=(str(detail)[:88]+"…") if len(str(detail))>88 else detail
    S.log.append((now(),kind,lane,detail,verdict))
    print(f"[{now():6.2f}s] {kind:6s} {lane:16s} {verdict:9s} {d}",flush=True)

async def ssh_fire(cmd,timeout=150):
    S.shots+=1; S.inflight+=1; S.maxc=max(S.maxc,S.inflight)
    try:
        p=await asyncio.create_subprocess_exec("ssh",*CTRL,JAGG,cmd,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
        try: out,_=await asyncio.wait_for(p.communicate(),timeout=timeout)
        except asyncio.TimeoutError:
            try: p.kill()
            except Exception: pass
            return ""
        return out.decode(errors="replace")
    finally: S.inflight-=1

async def recon():
    # faithful to their recon(): nmap -sn discovery, then -sV, bind services, wp fingerprint
    await ssh_fire(f"nmap -sn {EDGE}.10-30 --min-rate 5000 2>/dev/null")  # discovery (shot)
    rng=f"{EDGE}.10-30"
    out=await ssh_fire(f"nmap -sV -p 21,22,53,80,110,139,443,445,3306,8080,9000 -T4 "
                       f"--min-rate 5000 {rng} -oG - 2>/dev/null",timeout=150)
    bind={}
    for line in out.splitlines():
        m=re.match(rf"Host: ({re.escape(EDGE)}\.\d+).*Ports: (.+)",line)
        if not m: continue
        ip,ports=m.group(1),m.group(2)
        for pspec in ports.split(","):
            f=pspec.split("/")
            if len(f)<7 or f[1].strip()!="open": continue
            port,name=f[0].strip(),f[4].strip()
            if name=="ftp": bind["ftp"]=ip
            elif name in ("domain","dns"): bind["dns"]=ip
            elif name in ("microsoft-ds","netbios-ssn","smb"): bind["smb"]=ip
            elif name in ("http","http-proxy") or port in ("80","8080"): bind["http"]=ip
    if bind.get("http"):
        fp=await ssh_fire(f"curl -s --max-time 8 -i http://{bind['http']}/ ; "
                          f"curl -s --max-time 6 http://{bind['http']}/wp-login.php -o /dev/null -w '%{{http_code}}'")
        if "wp-content" in fp or "wordpress" in fp.lower() or fp.strip().endswith(("200","302")):
            bind["wp"]=True
    ev("RECON","nmap-discover",f"bind={bind}","CONFIRMED")
    return bind

async def fire_lane(l):
    cmd=l.get("cmd") or (l["dyn"](S.dc) if l.get("dyn") and S.dc else None)
    if not cmd: ev("LANE",l["id"],"no cmd (dc unknown)","NEGATIVE"); return
    out=await ssh_fire(cmd)
    for m in FLAG_RE.findall(out): S.flags.setdefault(l["id"],m)
    try: ok=bool(l["hit"](out))
    except Exception: ok=False
    if l["id"]=="dns-axfr" and ok:
        m=re.search(rf"({re.escape(INT)}\.\d+)",out)
        if m: S.dc=m.group(1)
    verdict=None
    if not ok and l.get("amber") and out.strip():
        verdict=ask_17b(l["tag"],out); ok=bool(verdict)
    tag=("GOLD" if ok and l.get("gold") else "CONFIRMED" if ok else "NEGATIVE")
    ev("LANE",l["id"],f"{l['tag']}"+(f"  1.7b={verdict}" if verdict is not None else ""),tag)
    if ok and l.get("gives"):
        S.facts.add(l["gives"])
        if l["gives"]=="dc_owned": S.dc_cred=l["tag"]

async def run():
    ev("START","autocannon(theirs)",f"EDGE={EDGE} INT={INT}","-")
    bind=await recon()
    lanes={l["id"]:l for l in build_belt(bind)}
    ev("BELT","build_belt",f"{len(lanes)} lanes","-")
    sem=asyncio.Semaphore(CAP); started=set(); tasks={}
    async def guarded(l):
        async with sem: await fire_lane(l)
    def launch():
        for lid,l in lanes.items():
            if lid in started or not (l["needs"]<=S.facts): continue
            started.add(lid); t=asyncio.create_task(guarded(l)); tasks[t]=lid
    launch()
    while tasks:
        done,_=await asyncio.wait(list(tasks),return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            tasks.pop(t,None)
            try: t.result()
            except Exception as e: ev("ERR","lane",str(e),"EXC")
        launch()
    dt=now()
    owned="dc_owned" in S.facts
    print("\n"+"="*72)
    print(f"RESULT(theirs)  wall={dt:.2f}s  shots={S.shots}  max_conc={S.maxc}  "
          f"flags={len(S.flags)}  dc_owned={owned}  dc_cred={S.dc_cred}")
    for k,v in S.flags.items(): print(f"   FLAG {k:12s} {v}")
    print("="*72)
    json.dump({"engine":"theirs (autocannon warroom)","wall_s":round(dt,2),"shots":S.shots,
               "max_conc":S.maxc,"flags":dict(S.flags),"dc_owned":owned,"dc_cred":S.dc_cred,
               "creds_source":S.creds_source,
               "dc_detection":"smbclient -L (guest-vulnerable)",
               "pivot":"none (direct host route to internal /24)",
               "timeline":[[round(t,2),k,l,v] for t,k,l,_d,v in S.log]},
              open(f"{WORK}/result.json","w"),indent=2)

if __name__=="__main__":
    asyncio.run(run())
