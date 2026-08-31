#!/usr/bin/env python3
"""autoturret -> BS2 war-room bridge (CONTENT-TIER, not the manager).

The flash-autoturret grounds facts into run/autoturret.ops.jsonl (full values) and
run/recon.json (owned/flags). This bridge mirrors those into the BS2 map via bs2_emit so the
War Room UI, the strategist, and the escalation ladder all see the autoturret's live progress —
exactly the way the Opus claude-p hands used to call bs2_emit on every discovery.

Isolation: this runs ALONGSIDE the engine as its own process. It reads the OPS feed (full
fact text) — which is the content tier the operator's browser already sees — and writes only
the map. The manager (Claude) never runs this and never reads its inputs; the manager reads the
scrubbed autoturret.jsonl + telemetry.json + map.json only. Never raises; never blocks.

Usage:  autoturret_bs2_bridge.py <RUN_DIR> <TARGET_IP>
"""
import json, os, re, subprocess, sys, time

RUN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AUTOTURRET_RUN", "")
TARGET = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("GB_TARGET", "")
EMIT = os.environ.get("BS2_EMIT",
                      "/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria/bs2_emit.py")
OPS = os.path.join(RUN, "autoturret.ops.jsonl")
RECON = os.path.join(RUN, "recon.json")
POLL = float(os.environ.get("BRIDGE_POLL", "4"))


def emit(*args):
    try:
        subprocess.run(["python3", EMIT, *[str(a) for a in args]],
                       capture_output=True, timeout=20)
    except Exception:
        pass


_seen = set()


def _emit_fact(fact):
    fact = fact.strip()
    if not fact or fact in _seen:
        return
    _seen.add(fact)
    low = fact.lower()
    if "=" not in fact:
        return
    val = fact.split("=", 1)[1].strip()
    if low.startswith("flag="):
        emit("flag", "box", val, "autoturret")
    elif low.startswith(("cred=", "dc_cred=")):
        user = val.split(":", 1)[0]
        emit("cred", TARGET, user, "autoturret")
    elif low.startswith("hash="):
        emit("cred", TARGET, "hash-" + re.sub(r"[^A-Za-z0-9]", "", val)[:8], "autoturret")
    elif low.startswith("vhost="):
        emit("host", val, "web-vhost", "spotted")
    elif low.startswith("app="):
        host = val.split(":")[-1]
        emit("host", host, "web-app", "spotted")
    elif low.startswith(("shell", "rce_as", "dc_owned")):
        emit("host", TARGET, "foothold", "owned")


def scan_ops():
    if not os.path.exists(OPS):
        return
    try:
        for line in open(OPS, errors="ignore"):
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("kind") != "fact":
                continue
            txt = (d.get("text") or "").lstrip("⚑").strip()
            _emit_fact(txt)
    except Exception:
        pass


def scan_recon():
    try:
        d = json.load(open(RECON))
    except Exception:
        return
    for p in (d.get("proven_facts") or []):
        f = p.get("fact") if isinstance(p, dict) else p
        if f:
            _emit_fact(f)
    if d.get("owned"):
        emit("host", TARGET, "foothold", "owned")


MAP = os.environ.get("BS2_MAP",
                     "/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria/map.json")
TELE = os.environ.get("TELEMETRY",
                      "/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria/telemetry.json")


def refresh_telemetry():
    """Keep the war-room header + escalation-ladder progress signal live from the map."""
    try:
        m = json.load(open(MAP))
    except Exception:
        return
    owned = [h.get("ip") for h in m.get("hosts", []) if h.get("owned") or h.get("state") == "owned"]
    disc = [h.get("ip") for h in m.get("hosts", [])]
    flags = [f.get("value") if isinstance(f, dict) else f for f in m.get("flags", [])]
    phase = "owned" if owned else ("foothold" if flags else "recon")
    try:
        json.dump({"arm": "double-barrel", "phase": phase, "ts": int(time.time()),
                   "hosts_owned": owned, "hosts_discovered": disc,
                   "hops": len(m.get("pivots", [])), "flags": flags},
                  open(TELE, "w"))
    except Exception:
        pass


def main():
    if TARGET:
        emit("host", TARGET, "external-perimeter", "spotted")
    while True:
        scan_ops()
        scan_recon()
        refresh_telemetry()
        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
