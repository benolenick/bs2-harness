#!/usr/bin/env bash
# BS2 pentest system — preflight / proper start check.
# CHECK-ONLY. Never touches GPU0 (shared vLLM :8000 + ollama) — verifies, never starts it.
set -u
pass(){ printf "  \033[32mUP\033[0m   %-22s %s\n" "$1" "$2"; }
fail(){ printf "  \033[31mDOWN\033[0m %-22s -> %s\n" "$1" "$2"; }
code(){ curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$1" 2>/dev/null; }

echo "== BS2 pentest stack preflight =="
# 1. Ariadne planner (:8112) — the brain
c=$(code http://127.0.0.1:8112/health)
if [ "$c" = "200" ]; then
  ops=$(curl -s --max-time 3 http://127.0.0.1:8112/health | python3 -c "import sys,json;d=json.load(sys.stdin);print(f\"{d.get('operators','?')} ops, {d.get('knowledge','?')} facts\")" 2>/dev/null)
  pass "ariadne :8112" "$ops"
else fail "ariadne :8112" "cd /home/operator/ariadne && systemctl --user start ariadne (or python3 serve.py)"; fi
# 2. Local vLLM (:8000) — CHECK ONLY, never start (GPU0 shared, do not touch)
c=$(code http://127.0.0.1:8000/health)
[ "$c" = "200" ] && pass "vllm :8000 (GPU0)" "shared — do NOT restart" || fail "vllm :8000 (GPU0)" "ASK BEN — never auto-start GPU0"
# 3. BS2 UI (:8125)
c=$(code http://127.0.0.1:8125/)
[ "$c" = "200" ] || [ "$c" = "404" ] && pass "bs2 ui :8125" "serving" || fail "bs2 ui :8125" "cd battlestation && python3 server.py --ariadne-url http://127.0.0.1:8112"
# 4. SIGIL memory plane (topology on disk)
if [ -f /opt/bs2/.sigil/root.json ]; then
  n=$(ls /opt/bs2/.sigil/nodes/*.json 2>/dev/null | wc -l); pass "sigil topology" "root + $n nodes"
else fail "sigil topology" "python3 /opt/bs2/.sigil/build_topology.py"; fi
# 5. manager bridge importable
if python3 -c "import sys;sys.path.insert(0,'/opt/bs2/manager');import manager_bridge" 2>/dev/null; then
  pass "manager_bridge" "importable"
else fail "manager_bridge" "check /opt/bs2/manager/manager_bridge.py"; fi
# 6. governed seam tool
[ -f /opt/bs2/live/governed_seam.py ] && pass "governed_seam" "present (per-engagement ledger)" || fail "governed_seam" "missing"
# 7. SIGIL runtime lab (housekeeping + curation)
if python3 -c "import sys;sys.path.insert(0,'/mnt/sata/sigil-runtime-lab');from runtime.curation_cycle import run_curation_cycle;from runtime.housekeeping import HousekeepingController" 2>/dev/null; then
  pass "sigil runtime" "housekeeping + curation loaded"
else fail "sigil runtime" "check /mnt/sata/sigil-runtime-lab (is /mnt/sata mounted?)"; fi
echo "== end preflight =="
