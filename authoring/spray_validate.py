#!/usr/bin/env python3
"""Validation spray: fire the SAFE recon/enum cards from the deck at redmirror (via your-host),
bind templates, capture results, judge whether each card actually WORKS. Proves the
first cards are (a) the real attack cloud for this box and (b) mechanically sound.

SAFETY: only recon/enum phase, blast_radius none|low, no brute/exploit tools. Fires our
own VM through your-host. No governed_exec bypass — this is the validation lane, dial=semi floor.
"""
import sys, os, re, json, subprocess
sys.path.insert(0, '/opt/bs2/catalog')
sys.path.insert(0, '/opt/bs2/authoring')
import loader

DECK = "/opt/bs2/authoring/deck_linux_service.yaml"
MAP  = "/opt/bs2/live/redmirror/map.json"
JAGG = "om@192.0.2.10"
HOST = "192.0.2.10"

# template bindings for redmirror
SVC_PORT = {"ftp":21,"ssh":22,"smtp":25,"dns":53,"domain":53,"http":80,"pop3":110,
            "rpcbind":111,"imap":143,"imaps":993,"pop3s":995,"dovecot":110}
PARAMS = {
    "host": HOST, "target": HOST, "ip": HOST, "rhost": HOST,
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "userlist": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "resolver_list": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "candidate_list": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "threads": "20", "timing": "3", "wait": "3", "timeout": "5s", "min_cvss": "7.0",
    "anonymous_password": "anonymous", "sender": "root@redmirror",
    "output": "/tmp/vsp_out.txt", "remote_dir": "/",
    "user": "anonymous", "password": "anonymous", "username": "anonymous",
    "status_codes": "200,204,301,302,307,401,403", "filtered_codes": "404",
    "depth": "1", "report": "/tmp/ferox_redmirror.txt", "aggression": "1",
    "aggression_level": "1", "report_file": "/tmp/vsp_report.txt",
}
UNSAFE_TOOLS = {"hydra","ncrack","medusa","patator","msfconsole","msfvenom","sqlmap","swaks"}

def bind(inv, port):
    p = dict(PARAMS); p["port"] = str(port)
    def sub(m):
        k = m.group(1).strip()
        return p.get(k, m.group(0))
    return re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", sub, inv)

def port_for(card):
    for w in card.get("when", []):
        if isinstance(w, dict) and "port" in w:
            return w["port"]
    for w in card.get("when", []):
        if isinstance(w, dict) and "service" in w:
            return SVC_PORT.get(str(w["service"]).lower(), 0)
    return 0

def fire(inv, timeout=40):
    cmd = ["ssh","-o","BatchMode=yes","-o","ConnectTimeout=6", JAGG, f"timeout {timeout} {inv}"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout+15, text=True)
        return r.returncode, (r.stdout or "")[:600], (r.stderr or "")[:200]
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"

def main():
    import yaml
    deck = yaml.safe_load(open(DECK)) or []
    ctx = loader.facts_from_map(MAP)
    selected = loader.select(ctx, dial="semi", catalog=deck)
    # safe validation subset
    safe = [c for c in selected
            if c.get("phase") in ("recon","enum")
            and c.get("blast_radius","low") in ("none","low")
            and str(c.get("tool","")).split()[0] not in UNSAFE_TOOLS]
    print(f"deck {len(deck)} | selected(match redmirror) {len(selected)} | safe recon/enum to fire {len(safe)}\n")
    results = []
    for c in safe:
        inv = bind(c["invocation"], port_for(c))
        if "{{" in inv:
            missing = re.findall(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", inv)
            results.append((c["id"], "SKIP", f"needs {set(missing)}", "")); continue
        rc, out, err = fire(inv)
        nonempty = bool(out.strip())
        verdict = "WORKED" if (rc == 0 and nonempty) else ("FIRED-EMPTY" if rc==0 else f"FAIL rc={rc}")
        results.append((c["id"], verdict, inv[:70], out.strip().split("\n")[0][:80] if nonempty else err[:60]))
    print(f"{'CARD':32} {'VERDICT':13} EVIDENCE")
    for cid, v, inv, ev in results:
        print(f"{cid:32} {v:13} {ev}")
    worked = sum(1 for r in results if r[1]=="WORKED")
    print(f"\n=== {worked}/{len(safe)} safe cards WORKED against redmirror ===")
    json.dump([{"id":r[0],"verdict":r[1],"inv":r[2],"evidence":r[3]} for r in results],
              open("/opt/bs2/authoring/validation_report.json","w"), indent=1)

if __name__ == "__main__":
    main()
