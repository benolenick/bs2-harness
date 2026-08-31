#!/usr/bin/env python3
"""Content-blind validator: fire each web card through the engine's own fire_card + gate,
print ONLY id / phase / verdict / failure-class. Never emits response bodies (manager-safe)."""
import sys, subprocess, yaml
sys.path.insert(0, "/opt/bs2/catalog")
import bridge

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3060"

def run_cmd(cmd, target):
    try:
        r = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=60)
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return "timed out"
    except Exception as e:
        return f"error {e}"

recon = {"target": TARGET, "apps": {}, "bind": {"http": TARGET}, "services": ["http"],
         "unlocked_keys": [], "proven_facts": []}
cards = yaml.safe_load(open("/opt/bs2/catalog/web_cards.yaml"))

hit = miss = staged = 0
lines = []
for c in cards:
    v = bridge.resolve_vars(c, TARGET, recon)
    res = bridge.fire_card(c, TARGET, v, run_cmd)
    st = res.get("status")
    fc = res.get("fclass", "") or res.get("reason", "")[:24]
    if st == "hit":
        hit += 1; mark = "HIT "
    elif st in ("staged", "needs-gate"):
        staged += 1; mark = "STAGE"
    else:
        miss += 1; mark = "miss"
    src = res.get("src", "")
    lines.append(f"  {mark:5} {c['id']:32} [{c['phase']:7}] {('via '+src) if src else '':9} {fc}")

print(f"TARGET {TARGET}  —  {len(cards)} cards:  HIT={hit}  STAGE={staged}  miss={miss}")
print("\n".join(lines))
