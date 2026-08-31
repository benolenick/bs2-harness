#!/usr/bin/env python3
import re, json, subprocess, sys, yaml
sys.path.insert(0,'/opt/bs2/catalog'); sys.path.insert(0,'/opt/bs2')
JAGG="om@192.0.2.10"
DECK="/opt/bs2/catalog/deck_final.yaml"
HOST="192.0.2.10"
# real range ports (your-host's own 22/80 excluded)
SVC_PORT={"ftp":21,"ssh":2222,"smtp":25,"http":8080,"https":8080,"smb":445,"samba":445,
          "netbios-ssn":445,"smtps":25}
PRESENT={"ftp","ssh","smtp","http","smb","samba","netbios-ssn"}
PRESENT_PORTS={21,2222,25,8080,8081,139,445}
WL="/usr/share/seclists/Discovery/Web-Content/common.txt"
PARAMS={
 "host":HOST,"target":HOST,"target_host":HOST,"probe_host":HOST,"probe_ip":HOST,
 "url":f"http://{HOST}:8080/","scheme":"http","domain":"redrange.local","zone":"redrange.local",
 "wordlist":WL,"namelist":WL,"userlist":"/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
 "passlist":"/usr/share/seclists/Discovery/Web-Content/common.txt",
 "password_file":"/usr/share/seclists/Discovery/Web-Content/common.txt",
 "resolvers":"/etc/resolv.conf","resolver":"192.0.2.10","resolver_list":"192.0.2.10",
 "user":"admin","password":"admin","pass":"admin","threads":"15","rate":"50","timeout":"15",
 "depth":"1","status_codes":"200,204,301,302,307,401,403","output":"/tmp/rr_out.txt",
 "results_file":"/tmp/rr_out.txt","out_file":"/tmp/rr_out.txt","output_dir":"/tmp/rr_out",
 "version":"1","product":"apache","path":"/","file":"/etc/passwd","command":"id",
 "candidate_list":"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
 "templates":"cves","module":"auxiliary/scanner/ftp/anonymous","cve":"CVE-2021-0000",
}
UNSAFE={"hydra","ncrack","medusa","patator","msfconsole","msfvenom","sqlmap","swaks",
        "wpscan","nikto","nuclei"}  # brute/exploit/noisy -> governed_exec only, not this bench
def present(card):
    for w in card.get("when",[]):
        if isinstance(w,dict):
            if str(w.get("service","")).lower() in PRESENT: return True
            if w.get("port") in PRESENT_PORTS: return True
    return False
def port_for(card):
    for w in card.get("when",[]):
        if isinstance(w,dict) and str(w.get("service","")).lower() in SVC_PORT:
            return SVC_PORT[str(w["service"]).lower()]
    for w in card.get("when",[]):
        if isinstance(w,dict) and w.get("port") in PRESENT_PORTS: return w["port"]
    return 0
def bind(inv,port):
    p=dict(PARAMS); p["port"]=str(port or 80)
    return re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", lambda m:p.get(m.group(1).strip(),m.group(0)), inv)
def fire(inv,t=25):
    cmd=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=6",JAGG,
         f"export PATH=$PATH:/usr/bin:/usr/local/bin:/snap/bin; timeout {t} {inv}"]
    try:
        r=subprocess.run(cmd,capture_output=True,timeout=t+15,text=True)
        return r.returncode,(r.stdout or "")[:800],(r.stderr or "")[:300]
    except subprocess.TimeoutExpired:
        return 124,"","TIMEOUT"
def main():
    deck=yaml.safe_load(open(DECK)) or []
    on=[c for c in deck if present(c)]
    fireset=[c for c in on if c.get("phase") in ("recon","enum","loot")
             and c.get("blast_radius","low") in ("none","low")
             and str(c.get("tool","")).split()[0] not in UNSAFE]
    from collections import Counter
    ph=Counter(c.get("phase") for c in on)
    print(f"deck {len(deck)} | match-range terrain {len(on)} {dict(ph)} | safe live-fire {len(fireset)}\n")
    res=[]
    for c in fireset:
        inv=bind(c["invocation"],port_for(c))
        miss=re.findall(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}",inv)
        if miss:
            res.append((c["id"],c["tool"],"SKIP-PARAM",f"needs {sorted(set(miss))}","")); continue
        rc,out,err=fire(inv)
        blob=(out+" "+err)
        landed = ("RANGE{" in blob) or ("HTB{" in blob)
        ne=bool(out.strip())
        if landed: v="LANDED"
        elif rc==0 and ne: v="WORKED"
        elif rc==0: v="FIRED-EMPTY"
        elif rc==127: v="NO-TOOL"
        else: v=f"FAIL{rc}"
        ev=(out.strip().split(chr(10))[0][:90] if ne else err.strip()[:70])
        res.append((c["id"],c["tool"],v,ev,inv[:90]))
    print(f"{'CARD':40} {'TOOL':12} {'VERDICT':12} EVIDENCE")
    for cid,tool,v,ev,_ in res:
        print(f"{cid:40.40} {tool:12.12} {v:12} {ev}")
    from collections import Counter as C
    vc=C(r[2] for r in res)
    print(f"\n=== verdicts: {dict(vc)} ===")
    print(f"deck coverage: {len(on)}/{len(deck)} cards match this box's terrain")
    json.dump([{"id":r[0],"tool":r[1],"verdict":r[2],"evidence":r[3],"inv":r[4]} for r in res],
              open("/opt/bs2/authoring/validation_report_range.json","w"),indent=1)
    print("report -> authoring/validation_report_range.json")
main()
