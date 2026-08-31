#!/usr/bin/env bash
# Standalone HANDS LOOP with all 3 manager levers. Runs against an EXISTING $ATRUN (no state
# wipe) and does NOT relaunch support procs — so it can hot-swap into a live run without losing
# recon. Usage: run_hands_loop.sh <TARGET> <ATRUN> <DIR> <DEADLINE_EPOCH>
set -uo pipefail
GB=/opt/bs2/live
TARGET="${1:?target}"; ATRUN="${2:?atrun}"; DIR="${3:?dir}"; DEADLINE="${4:?deadline}"
AT_TTL="${AT_TTL:-1500}"
export AUTOTURRET_CATALOG=1 GB_CATALOG=/opt/bs2/catalog/deck_run.yaml GB_JUDGE=1
export GB_LHOST="${ATTACKER:-10.10.14.153}" GB_ARIADNE=http://127.0.0.1:8112
export GB_MEMORIA_SSH="${GB_MEMORIA_SSH:-your-host}" GB_MEMORIA_URL="${GB_MEMORIA_URL:-http://127.0.0.1:8009/search}"
export GB_KNOWLEDGE=1 GB_MANAGER_DIRECTIVES="$ATRUN/manager_directives.md"
export TROOPER_BASE=https://api.deepseek.com TROOPER_MODEL=deepseek-v4-flash
export TROOPER_KEY_FILE=/opt/bs2/.ds_key TROOPER_MAX_TOKENS=3000 TROOPER_CMD_TIMEOUT=40
unset TROOPER_EXEC_SSH
echo "$(date +%H:%M:%S) HANDS-LOOP (levers) attached to $ATRUN, deadline=$(date -d @$DEADLINE +%H:%M:%S)" >> "$DIR/run.status"
attempt=0; LAST_FSIG=x
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  [ -f "$DIR/CAPTURED" ] && { echo "$(date +%H:%M:%S) CAPTURED — stop" >> "$DIR/run.status"; break; }
  if python3 -c "import json,sys;d=json.load(open('$ATRUN/recon.json'));sys.exit(0 if d.get('owned') else 1)" 2>/dev/null; then
    echo "$(date +%H:%M:%S) OWNED — stop" >> "$DIR/run.status"; touch "$DIR/CAPTURED"; break; fi
  # LEVER 1: manager HOLD
  if [ -f "$ATRUN/hold" ]; then echo "$(date +%H:%M:%S) HELD by manager — waiting" >> "$DIR/run.status"; sleep 15; continue; fi
  now=$(date +%s); left=$(( DEADLINE - now )); [ "$left" -lt 60 ] && break
  ttl=$AT_TTL; [ "$ttl" -gt "$left" ] && ttl=$left
  attempt=$((attempt+1))
  # LEVER 1: fact-delta note
  FSIG=$(python3 -c "import json;d=json.load(open('$ATRUN/recon.json'));print(len(d.get('proven_facts') or []))" 2>/dev/null || echo 0)
  [ "${FSIG:-0}" = "${LAST_FSIG}" ] && echo "$(date +%H:%M:%S) NOTE: no new facts since last sweep (proven=$FSIG)" >> "$DIR/run.status"
  LAST_FSIG=$FSIG
  # LEVER 2: resettable goal
  PLAN=$(cat "$ATRUN/planner_goal" 2>/dev/null | tr -d '[:space:]'); PLAN="${PLAN:-rce}"
  echo "$(date +%H:%M:%S) hands-loop attempt=$attempt ttl=${ttl}s goal=$PLAN" >> "$DIR/run.status"
  start=$(date +%s)
  ( cd "$GB" && AUTOTURRET_RUN="$ATRUN" AUTOTURRET_TTL="$ttl" \
      python3 autoturret.py --target "$TARGET" --dial full --planner "$PLAN" \
        --run-dir "$ATRUN" --ttl "$ttl" >> "$DIR/autoturret.iter.log" 2>&1 )
  dur=$(( $(date +%s) - start ))
  echo "$(date +%H:%M:%S) hands-loop attempt=$attempt done dur=${dur}s" >> "$DIR/run.status"
  [ "$dur" -lt 20 ] && sleep 10 || sleep 3
done
echo "$(date +%H:%M:%S) HANDS-LOOP complete (attempts=$attempt)" >> "$DIR/run.status"
