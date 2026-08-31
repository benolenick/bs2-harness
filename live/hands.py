#!/usr/bin/env python3
"""hands — the recon executor. THE MISSING LINK between the cartographer's frontier and a
map that actually fills itself in.

The cartographer records; it never touches the target (by design — a recorder that runs tools
rots back into hardcoded recipes). The HANDS are the piece that was missing: they read a
frontier edge ("8080 → dirs, vhosts, tech-fingerprint"), run the RIGHT your-host tool with the
RIGHT wordlist against the target, scrub the output to observations, and fold them back into
the cartographer so the map grows and new nodes appear. Loop until the frontier dries.

    cartographer.frontier() ──► hands.run() ──[your-host arsenal]──► observations ──► cartographer.fold()

WHERE IT RUNS: your-host (fleet .129) — the box with the arsenal (nmap/gobuster/ffuf/whatweb/
netexec/nuclei/searchsploit + seclists + wordlists + the RAG corpus). Every target-touching
command runs THERE, over ssh, with a timeout.

THE SAFETY LINE (matches HOW_I_BROKE_BATTLESTATION...): hands does DISCOVERY only. Enumeration
rituals are standard tradecraft ("an http port always gets gobuster") — safe to encode. Any
ritual that is an EXPLOITATION decision (default-creds, injection, authz-diff, cred-spray,
exploit-chain) is DEFERRED to the manager, never fired here — and deferrals are LOGGED, never
silently skipped. hands proposes no exploits; it only makes the map real.

    hands.py run  --run-dir DIR [--target IP] [--top N] [--dry-run] [--host your-host]
    hands.py loop --run-dir DIR [--target IP] [--rounds K] [--dry-run]   # drive until frontier dry
"""
from __future__ import annotations
import argparse, json, os, re, shlex, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cartographer as CG
from recon_record import ReconObservation

JAGG = os.environ.get("HANDS_HOST", "your-host")
WL_DIR   = "/usr/share/seclists/Discovery/Web-Content/common.txt"
WL_VHOST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# ---- ritual -> recon action. Each action: the your-host command + a parser(out)->observations. ----
# Only DISCOVERY rituals live here. Exploitation rituals are in DEFERRED below (logged, not run).
def _http_base(ctx):
    scheme = "https" if ctx["service"] == "https" or ctx["port"] in (443, 8443) else "http"
    return f"{scheme}://{ctx['target']}:{ctx['port']}"

def _cmd_dirs(ctx):
    url = _http_base(ctx)
    # portable: gobuster if present, else ffuf (reformatted to gobuster-style "/path (Status: N)")
    return (f"if command -v gobuster >/dev/null 2>&1; then "
            f"gobuster dir -u {url} -w {WL_DIR} -q -t 40 --no-error -k 2>/dev/null; "
            f"elif command -v ffuf >/dev/null 2>&1; then "
            f"ffuf -u {url}/FUZZ -w {WL_DIR} -mc 200,204,301,302,307,401,403 -s -t 40 2>/dev/null "
            f"| sed -e 's#^#/#' -e 's#$# (Status: 200)#'; fi")
def _parse_dirs(out, ctx):
    obs = []
    for m in re.finditer(r"^(/[^\s]*)\s+\(Status:\s*(\d+)", out, re.M):
        obs.append(f"web{ctx['port']}={m.group(1)} (status {m.group(2)})")
    return obs

def _cmd_vhosts(ctx):
    return (f"gobuster vhost -u {_http_base(ctx)} -w {WL_VHOST} -q --no-error -k "
            f"--append-domain 2>/dev/null | head -40")
def _parse_vhosts(out, ctx):
    return [f"vhost: {m.group(1)}" for m in re.finditer(r"Found:\s*([a-z0-9.\-]+)", out, re.I)]

def _cmd_tech(ctx):
    url = _http_base(ctx)
    # whatweb if present, else a curl fingerprint: headers + generator/app tells (wordpress/gitlab/...)
    return (f"if command -v whatweb >/dev/null 2>&1; then whatweb -a1 --color=never {url} 2>/dev/null | head -5; "
            f"else {{ curl -s -I --max-time 12 {url}; curl -s --max-time 12 {url} "
            f"| grep -ioE 'wp-content|wp-includes|wordpress|<meta name=\"generator\"[^>]*|gitlab|osticket|joomla|drupal|<title>[^<]*'; }} "
            f"| tr '\n' ' '; fi")
def _parse_tech(out, ctx):
    # whatweb dumps plugin names; feed the whole line back as a web<port>= fact so the
    # cartographer's app fingerprinter (wordpress/osticket/gitlab/...) can catch it.
    line = out.strip().splitlines()[0] if out.strip() else ""
    return [f"web{ctx['port']}={line[:400]}"] if line else []

def _cmd_axfr(ctx):
    dom = ctx.get("domain") or os.environ.get("HANDS_DOMAIN", "")
    # full AXFR (not +short) so TXT flags and A-records for internal hosts are visible
    return f"dig axfr @{ctx['target']} {dom} 2>/dev/null | head -120"
def _parse_axfr(out, ctx):
    obs = []
    for m in re.finditer(r"^([a-z0-9_.\-]+)\.\s+\d+\s+IN\s+(A|CNAME|NS)\s+(\S+)", out, re.M | re.I):
        obs.append(f"vhost: {m.group(1)}")
        ipv = m.group(3).rstrip('.')
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ipv):
            obs.append(f"web{ctx.get('port',53)}=dns-record {m.group(1)} -> {ipv}")
    # internal hosts revealed by the zone (pivot breadcrumbs) + any embedded flag
    for ip in set(re.findall(r"\b(172\.16\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b", out)):
        obs.append(f"enum=internal-host {ip}")
    return obs

def _cmd_ftp_anon(ctx):
    t, p = ctx['target'], ctx['port']
    # list the anon root, then cat each readable file so its CONTENT (flags, creds) is captured
    return (f"L=$(curl -s --max-time 15 ftp://{t}:{p}/ 2>/dev/null); echo \"$L\" | head -30; "
            f"for f in $(echo \"$L\" | awk '{{print $NF}}' | grep -iE '\\.(txt|md|conf|cfg|bak|log|xml|ini)$' | head -8); do "
            f"echo \"=== ftp:$f ===\"; curl -s --max-time 12 ftp://{t}:{p}/$f 2>/dev/null | head -20; done")
def _parse_ftp_anon(out, ctx):
    obs = []
    for l in out.strip().splitlines():
        l = l.strip()
        if not l: continue
        # a directory-listing row ends in a filename; note it readable
        if re.search(r"\s\S+$", l) and not l.startswith("===") and "HTB{" not in l:
            obs.append(f"ftp=anonymous:readable:{l.split()[-1]}")
    return obs[:12]

def _cmd_smb_shares(ctx):
    return f"netexec smb {ctx['target']} --shares 2>/dev/null | head -40"
def _parse_smb_shares(out, ctx):
    return [f"share: {m.group(1)}" for m in re.finditer(r"READ|WRITE.*?\b([A-Za-z0-9$_\-]+)\b", out)]

def _cmd_smb_users(ctx):
    return f"netexec smb {ctx['target']} --users 2>/dev/null | head -60"
def _parse_smb_users(out, ctx):
    return [f"user: {m.group(1)}" for m in re.finditer(r"\\([A-Za-z0-9._\-]+)\s", out)]

def _cmd_cve(ctx):
    q = (ctx.get("product") or ctx.get("app") or "").strip()
    q = re.sub(r"[^A-Za-z0-9. ]", " ", q)
    return f"searchsploit {shlex.quote(q)} 2>/dev/null | head -25" if q else "true"
def _parse_cve(out, ctx):
    # labels only (exploit titles), content-blind — a signal the manager/Ariadne can act on.
    # searchsploit prints "Title | Path"; skip its [i]/[!] info lines, rules, and headers.
    hits = []
    for l in out.splitlines():
        s = l.strip()
        if not s or s[0] in "[-" or "Exploit Title" in s or "|" not in s:
            continue
        title = s.split("|")[0].strip()
        if title:
            hits.append(title)
    return [f"cve-candidate: {h[:120]}" for h in hits[:6]]

ACTIONS = {
    "dirs":             (_cmd_dirs, _parse_dirs),
    "vhosts":           (_cmd_vhosts, _parse_vhosts),
    "tech-fingerprint": (_cmd_tech, _parse_tech),
    "axfr":             (_cmd_axfr, _parse_axfr),
    "anon-login":       (_cmd_ftp_anon, _parse_ftp_anon),
    "shares":           (_cmd_smb_shares, _parse_smb_shares),
    "users":            (_cmd_smb_users, _parse_smb_users),
    "version-cve":      (_cmd_cve, _parse_cve),
    "cve-lookup":       (_cmd_cve, _parse_cve),
    "rpcinfo":          (lambda c: f"rpcinfo -p {c['target']} 2>/dev/null | head", lambda o, c: []),
}
# rituals hands must NOT run — exploitation decisions the manager owns. Logged, never fired.
DEFERRED = {"default-creds", "params-fuzz", "authz-diff", "injection-signals",
            "spray-across-services", "auth-to-app", "known-exploit-chain", "null-session",
            "user-enum", "user-enum-vrfy", "kerberoast-if-ad", "writable-check", "list-files",
            "subdomain-brute", "nfs-shares", "creds-if-known", "as-spray-target",
            "full-port-sweep", "internal-ports-if-shell", "treat-as-new-web-surface", "enumerate"}


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

def _jagg(cmd, host, timeout=180, dry=False):
    if dry:
        return f"[DRY] {cmd}", 0
    # §10.1: survey recon is target contact too -> route through the ONE primitive (governed
    # when a seam is open, witnessed-fallback ssh to `host` otherwise). rc is reconstructed
    # from the primitive's failure markers so _result_marker's rc==0 clean-check is preserved.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__))))
    import target_exec as _texec
    out = _texec.run(cmd, action_class="web.recon", timeout=timeout, ssh_host=host)
    low = out.lstrip()
    if low.startswith("[timeout") or out.rstrip().endswith("(timeout)"):
        rc = 124
    elif low.startswith(("[error", "(error", "[GOVERNED", "[target-exec BLOCKED")):
        rc = 1
    else:
        rc = 0
    return _ANSI.sub("", out), rc


def _result_marker(edge_id, ritual, out, rc):
    """Return coverage only for a clean command result; otherwise return failure evidence."""
    if rc == 0 and not re.match(r"^\s*\[(?:timeout\]|error:)", out or "", re.I):
        return f"enum={edge_id}:{ritual}"
    return f"failed={edge_id}:{ritual}:rc{rc}"


def _ctx_for(node, target):
    m = node.get("meta", {})
    return {"target": target, "port": m.get("port") or 80, "service": m.get("service") or "http",
            "product": m.get("product", ""), "app": m.get("app", ""),
            "handle": m.get("handle", ""), "domain": m.get("domain", "")}


def run(run_dir, target=None, top=1, dry=False, host=JAGG, ts=None):
    """Take the top frontier edge(s), run every runnable ritual on your-host, fold results back."""
    ts = int(ts if ts is not None else (int(os.environ.get("HANDS_TS", "0")) or int(time.time())))
    C = CG.Cartographer(run_dir)
    if not C.doc["nodes"]:
        C.ingest_map_json(ts)
    target = target or C.doc.get("target")
    if not target:
        print("no target (map.json empty and --target not given)"); return
    fr = C.frontier(top)
    if not fr:
        print("frontier dry — nothing to enumerate"); return
    all_obs, report = [], []
    for edge in fr:
        node = C.doc["nodes"][edge["id"]]
        ctx = _ctx_for(node, target)
        for ritual in edge["suggest"]:
            if ritual in DEFERRED:
                report.append(f"  defer  {edge['id']}:{ritual}  (manager-authored, not fired)")
                continue
            act = ACTIONS.get(ritual)
            if not act:
                report.append(f"  skip   {edge['id']}:{ritual}  (no recon action)")
                continue
            cmd_fn, parse_fn = act
            out, rc = _jagg(cmd_fn(ctx), host, dry=dry)
            obs = [] if dry else parse_fn(out, ctx)
            # structural observations spawn/updates nodes globally (fold); free-form findings
            # (cve-candidate titles, etc.) attach as notes to the node we actually probed.
            for o in obs:
                if re.match(r"(web\d|cred=|vhost:|share:|ftp=|user:|shell=|rce=|foothold=|done=|dead=|enum=)", o):
                    all_obs.append(o)
                elif not dry:
                    C.add_note(edge["id"], o, ts)
            result_marker = _result_marker(edge["id"], ritual, out, rc)
            all_obs.append(result_marker)
            if result_marker.startswith("failed="):
                report.append(f"  FAIL   {edge['id']}:{ritual}  (rc={rc}, not marked covered)")
            report.append(f"  RAN    {edge['id']}:{ritual}  ->  {len(obs)} observations"
                          + (f"   {cmd_fn(ctx)[:80]}" if dry else ""))
    # Failure markers are human-visible evidence only.  CG.fold forwards unknown strings
    # through its observation parser, so keep them out of the lifecycle/discovery fold.
    fold_obs = [o for o in all_obs if not o.startswith("failed=")]
    if not dry and all_obs:
        C.fold(fold_obs, ts)
        C.save(ts)
    print(f"# hands on {target} via {host}{'  [DRY-RUN]' if dry else ''}")
    print("\n".join(report) or "  (nothing runnable on the top edge)")
    if not dry:
        print(f"# folded {len(fold_obs)} observations; frontier now:")
        for r in C.frontier(6):
            print(f"    {r['score']:6.1f}  {r['kind']:8} {r['label'][:40]:40} → {', '.join(r['suggest'][:3])}")


def gnmap_ports(text):
    """Extract open ports from nmap grepable output."""
    ports = []
    for line in str(text or "").splitlines():
        if "Ports:" not in line:
            continue
        for m in re.finditer(r"(\d{1,5})/open(?:[|]filtered)?/", line):
            port = int(m.group(1))
            if port not in ports:
                ports.append(port)
    return sorted(ports)


_WELL_KNOWN = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
               110: "pop3", 139: "smb", 143: "imap", 161: "snmp", 389: "ldap",
               443: "https", 445: "smb", 1433: "mssql", 2049: "nfs", 3306: "mysql",
               3389: "rdp", 5432: "postgres", 6379: "redis", 27017: "mongodb",
               8000: "http", 8080: "http", 8443: "https"}


def _split_version(name):
    """'vsftpd3.0.3' / 'Apache httpd 2.4.41' -> (base, version). Only a TRAILING digit-run
    counts as a version, and only when the base left behind is free of digits."""
    name = str(name or "").strip()
    m = re.search(r"(\d[\d.]*)$", name)
    if m and not re.search(r"\d", name[:m.start(1)]):
        return (name[:m.start(1)].strip(" .-_") or name, m.group(1))
    return name, ""


def gnmap_surface(text, target, fallback_ports=None):
    """Build a surface map from nmap -sV grepable output
    ('.../open/tcp//ftp//vsftpd 3.0.3/...' -> {hosts:[{ip, ports:[...]}]})."""
    ports = {}
    for line in str(text or "").splitlines():
        if "Ports:" not in line:
            continue
        m = re.search(r"Ports:\s*(.*)", line)
        for ent in (m.group(1) or "").split(","):
            parts = ent.strip().split("/")
            # gnmap entry layout: port/state/proto/OWNER/service/RPCinfo/version/...
            if len(parts) < 5 or "open" not in parts[1]:
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            svc_field = parts[4].strip()
            prod_field = parts[6].strip() if len(parts) > 6 else ""
            prod_field = re.sub(r"\s*\(.*\)\s*$", "", prod_field)   # drop '((Ubuntu))' noise
            name = svc_field or _WELL_KNOWN.get(port, "unknown")
            base, ver = _split_version(prod_field) if prod_field else ("", "")
            if name == "unknown" and base:
                name = base
            ports[port] = {"port": port, "name": name,
                           "product": (prod_field or base or "")[:60],
                           "version": ver}
    for p in (fallback_ports or []):
        ports.setdefault(p, {"port": p, "name": _WELL_KNOWN.get(p, "unknown"),
                             "product": "", "version": ""})
    if not ports:
        return None
    return {"target": target,
            "hosts": [{"ip": target, "ports": sorted(ports.values(), key=lambda p: p["port"])}]}


def recon_sweep(target, runner, budget=480, records=None, ports=None):
    """DETERMINISTIC step-0 recon — hands' canonical open: full port sweep + service/version
    scan through the §10.1 door (via `runner`), parsed into a cartographer surface map.
    Fail-soft: returns None on any failure; the caller decides what happens next.

    `ports`: a charter-scoped port list (e.g. a local lab app's known ports). When set,
    discovery is SKIPPED — hands version-scans exactly these ports and nothing else, so a
    shared host (localhost) is never swept beyond the engagement's declared scope.

    `runner` is injectable: runner(cmd, timeout) -> output string. The CALLER supplies a
    §10.1-backed runner (hands gathers, it never opens its own execution path) — e.g.
    `lambda cmd, t: TEXEC.run(cmd, target, action_class="web.recon", timeout=t)`.
    Defaults to the §10.1 primitive over ssh (_jagg). Zero LLM tokens in this stage."""
    runner = runner or (lambda c, t: _jagg(c, host=JAGG, timeout=t)[0])
    t0 = time.time()
    tag = str(int(time.time()))
    gnmap = f"/tmp/gb_ritual_{tag}.gnmap"
    vgnmap = f"/tmp/gb_ritual_v_{tag}.gnmap"
    try:
        if ports:
            open_ports = sorted({int(p) for p in ports if str(p).isdigit()})
            if not open_ports:
                return None                     # charter-scoped: nothing declared to sweep
        else:
            sweep_out = runner(
                f"nmap -Pn -p- --min-rate 1500 -T4 -n --host-timeout 60s --max-retries 2 -oG {gnmap} {target} && cat {gnmap}",
                min(300, budget))
            open_ports = gnmap_ports(sweep_out)
            if not open_ports:
                sweep_out = runner(
                    f"nmap -Pn --top-ports 1000 -T4 -n --host-timeout 60s --max-retries 2 -oG {gnmap} {target} && cat {gnmap}",
                    min(300, budget))
                open_ports = gnmap_ports(sweep_out)
        surface = None
        if open_ports:
            remaining = budget - int(time.time() - t0)
            portlist = ",".join(str(p) for p in open_ports[:200])
            vscan = runner(
                f"nmap -Pn -sV --version-intensity 7 -T4 -n --host-timeout 60s --max-retries 2 -p {portlist} -oG {vgnmap} {target} && cat {vgnmap}",
                min(240, max(60, remaining)))
            surface = gnmap_surface(vscan, target, fallback_ports=open_ports)
            if surface is not None and records is not None:
                now = int(time.time())
                for port in surface["hosts"][0]["ports"]:
                    records.append(ReconObservation(
                        target=target, ts=now,
                        node_id=f"port:{target}:{port['port']}", kind="port",
                        data={**port, "fold": f"service={port['port']}:{port['name']}"},
                        evidence=["hands:nmap-service-scan"], producer="hands.recon_sweep",
                    ))
        runner(f"rm -f {gnmap} {vgnmap}", 30)
        return surface
    except Exception:
        return None


def verify_vhosts(target, names, runner, cap=12, records=None):
    """Batch content-compare a list of fuzz-born vhosts against the DEFAULT site.

    Kills ghosts in one command per step: fetch the default vhost body once, then diff
    each candidate's body/size against it — same-or-similar means the fuzz name was
    noise (dead=), a materially different body means a real vhost (verified=). Returns
    (dead, verified) name lists; the CALLER folds them (hands gathers, cartographer
    records).

    `runner` is injectable like sweep's: runner(cmd, timeout) -> output string, supplied
    by the caller. `names` come straight from the cartographer's UNVERIFIED vhost list
    (no ordering assumptions, capped at `cap`).
    """
    runner = runner or (lambda c, t: _jagg(c, JAGG, timeout=t)[0])
    names = [n for n in (names or [])][:cap]
    if not names:
        return [], []
    # default-body fingerprint: one fetch, size + first 2KB hash
    probe = (f"curl -sk --max-time 15 -o /dev/null -w '%{{size_download}}' http://{target}/; "
             f"curl -sk --max-time 15 http://{target}/ | md5sum")
    base = runner(probe, 60)
    base_m = re.search(r"^(\d+)", base)
    base_size = int(base_m.group(1)) if base_m else -1
    base_md5 = re.search(r"([0-9a-f]{32})", base)
    base_hash = base_md5.group(1) if base_md5 else ""
    dead, verified = [], []
    for name in names:
        out = runner(
            f"curl -sk --max-time 15 -H 'Host: {name}' -o /tmp/gb_vh_{name[:20]}.body "
            f"-w '%{{size_download}}' http://{target}/ && md5sum /tmp/gb_vh_{name[:20]}.body",
            60)
        size_m = re.search(r"^(\d+)", out)
        size = int(size_m.group(1)) if size_m else -1
        md5_m = re.search(r"([0-9a-f]{32})", out)
        h = md5_m.group(1) if md5_m else ""
        # size within 1% AND same hash (or both empty) => the fuzz name is noise
        same_size = size >= 0 and base_size >= 0 and abs(size - base_size) <= max(1, base_size // 100)
        same_hash = (not h and not base_hash) or (h and base_hash and h == base_hash)
        if same_size and same_hash:
            dead.append(name)
            if records is not None:
                records.append(ReconObservation(
                    target=target, ts=int(time.time()), node_id=f"vhost:{name.lower()}",
                    kind="negative", data={"fold": f"dead={name}"},
                    evidence=["hands:vhost-content-compare"],
                    producer="hands.verify_vhosts"))
        elif size > 0 and not same_hash:
            verified.append(name)
            if records is not None:
                records.append(ReconObservation(
                    target=target, ts=int(time.time()), node_id=f"vhost:{name.lower()}",
                    kind="verified", data={"fold": f"verified={name}"},
                    evidence=["hands:vhost-content-compare"],
                    producer="hands.verify_vhosts"))
        # anything else (fetch failed, in-between) stays unverifiable -> leave UNVERIFIED
    return dead, verified


def loop(run_dir, target=None, rounds=6, dry=False, host=JAGG):
    """Drive discovery until the frontier dries or rounds run out — the map making itself."""
    ts0 = int(os.environ.get("HANDS_TS", "0")) or 0
    for i in range(rounds):
        print(f"\n===== hands round {i+1}/{rounds} =====")
        C = CG.Cartographer(run_dir)
        # bootstrap: on the first round the map hasn't been ingested yet, so the frontier
        # guard would false-fire "dry". Seed nodes from map.json before checking. (loopfix)
        if not C.doc["nodes"]:
            C.ingest_map_json(ts0)
            C.save(ts0)
        if not C.frontier(1):
            print("frontier dry — discovery complete"); break
        run(run_dir, target=target, top=1, dry=dry, host=host)


def main():
    ap = argparse.ArgumentParser(description="hands — recon executor over the your-host arsenal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("run", "loop"):
        s = sub.add_parser(c)
        s.add_argument("--run-dir", required=True)
        s.add_argument("--target")
        s.add_argument("--dry-run", action="store_true")
        s.add_argument("--host", default=JAGG)
        s.add_argument("--top", type=int, default=1)
        if c == "loop":
            s.add_argument("--rounds", type=int, default=6)
    a = ap.parse_args()
    if a.cmd == "run":
        run(a.run_dir, target=a.target, top=a.top, dry=a.dry_run, host=a.host)
    else:
        loop(a.run_dir, target=a.target, rounds=a.rounds, dry=a.dry_run, host=a.host)


if __name__ == "__main__":
    main()
