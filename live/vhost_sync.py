#!/usr/bin/env python3
"""vhost_sync.py — auto-provision /etc/hosts from discovered vhosts so troopers can resolve.

The engine does the zone transfer (that's flag #1 on inlanefreight) and web-enum, so it ALREADY
knows every vhost — but nothing wrote them to the resolver, so manually-dispatched troopers died
at DNS. This closes that gap: harvest vhosts from the run's raw recon + recon.json apps and write
a single managed block to /etc/hosts (idempotent, marker-delimited). Safe to run repeatedly.

Usage: sudo python3 vhost_sync.py --target 198.51.100.10 --run-dir /path/to/atrun
       (or run via the launcher; needs root only to write /etc/hosts)
"""
import argparse, json, os, re, subprocess, sys

MARK_A = "# >>> gunbelt vhost_sync (auto) >>>"
MARK_B = "# <<< gunbelt vhost_sync (auto) <<<"
VHOST_RE = re.compile(r"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.(?:local|htb))\b", re.I)

def harvest(run_dir):
    names = set()
    raw = os.path.join(run_dir, "raw")
    for fn in ("dns-axfr.txt", "web-enum.txt", "ftp-anon.txt"):
        p = os.path.join(raw, fn)
        if os.path.exists(p):
            try: names |= {m.lower() for m in VHOST_RE.findall(open(p, errors="ignore").read())}
            except Exception: pass
    rj = os.path.join(run_dir, "recon.json")
    if os.path.exists(rj):
        try:
            d = json.load(open(rj)); apps = d.get("apps") or {}
            for v in (apps.values() if isinstance(apps, dict) else []):
                if isinstance(v, str): names |= {m.lower() for m in VHOST_RE.findall(v)}
        except Exception: pass
    # drop obvious non-vhost noise
    return sorted(n for n in names if not n.endswith((".png.local", ".css.local", ".js.local")))

def write_hosts(target, names, apex=None):
    if not names and not apex: return 0
    if apex: names = sorted(set(names) | {apex})
    block = [MARK_A, f"{target} " + " ".join(names), MARK_B]
    try:
        cur = open("/etc/hosts").read()
    except Exception:
        cur = ""
    if MARK_A in cur and MARK_B in cur:
        cur = re.sub(re.escape(MARK_A) + r".*?" + re.escape(MARK_B), "\n".join(block), cur, flags=re.S)
    else:
        cur = cur.rstrip("\n") + "\n" + "\n".join(block) + "\n"
    open("/etc/hosts", "w").write(cur)
    return len(names)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--apex", default="", help="optional apex domain (e.g. inlanefreight.local)")
    a = ap.parse_args()
    names = harvest(a.run_dir)
    apex = a.apex or None
    # infer apex from the commonest 2-label suffix if not given
    if not apex and names:
        from collections import Counter
        suf = Counter(".".join(n.split(".")[-2:]) for n in names)
        apex = suf.most_common(1)[0][0]
    try:
        n = write_hosts(a.target, names, apex)
    except PermissionError:
        print("need root to write /etc/hosts (run under sudo)", file=sys.stderr); sys.exit(2)
    print(f"vhost_sync: {n} name(s) -> {a.target}" + (f" (apex {apex})" if apex else ""))
    if names: print("  " + ", ".join(names))
