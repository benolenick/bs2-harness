#!/usr/bin/env bash
# =============================================================================
# run_all_lanes — fire ALL our attack lanes at juice-shop in a SEQUENTIAL RELAY,
# into ONE governed battle you watch live at http://127.0.0.1:8126.
#   Lane 1  governed sighted attacker (claude -p -> gexec)   [fills :8126]
#   Lane 2  L2 expert dispatch: sqli + auth-bypass + BAC      [fills :8126]
#   Lane 3  AUTOTURRET recipe-spray (own War Room, own port)  [fires beside seam]
# (Excludes L3 "deep all-specialist".) Lanes run back-to-back so no two writers
# touch the event-sourced ledger at once; promotion runs BETWEEN lanes only.
#
#   run_all_lanes.sh [TARGET]   env  MODEL=claude-sonnet-5  PORT=8126
# =============================================================================
set -uo pipefail
GB=/opt/bs2/live
BS2=/mnt/sata/htb-bakeoff/bs2-governed-wt
S_INT1="$BS2/battlestation/static/intake.json"; S_INT2="/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/static/intake.json"
S_MGR1="$BS2/battlestation/static/manager.json"; S_MGR2="/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/static/manager.json"
TARGET="${1:-http://127.0.0.1:3060}"
CONTAINER="${CONTAINER:-juice-bs2-wb}"; PORT="${PORT:-8126}"; MODEL="${MODEL:-claude-sonnet-5}"
L1_MIN="${L1_MIN:-8}"; L2_MIN="${L2_MIN:-10}"; L3_MIN="${L3_MIN:-6}"
RUN="$GB/engagements/live_$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9' '_' | sed 's/__*/_/g;s/^_//;s/_$//')"
DONE="$RUN/RELAY_DONE"; LANE="$RUN/current_lane"
log(){ echo "$(date +%H:%M:%S) $*" | tee -a "$RUN/live.status"; }
feeds(){ local run="${1:-}"; python3 "$GB/intake_feed.py" --run-dir "$RUN" --live $run --out "$S_INT1" --out "$S_INT2" >/dev/null 2>&1 || true
         python3 "$GB/manager_feed.py" --run-dir "$RUN" $run --out "$S_MGR1" --out "$S_MGR2" >/dev/null 2>&1 || true; }
promote(){ python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" --promote >>"$RUN/map.log" 2>&1 || true; }

rm -rf "$RUN"; mkdir -p "$RUN"

# --- SETUP: fresh target, seam, surface map, serve --------------------------
log "[setup] resetting $CONTAINER (fresh board)"
docker restart "$CONTAINER" >/dev/null 2>&1 || { log "FATAL docker restart"; exit 1; }
for i in $(seq 1 40); do
  n="$(curl -s --max-time 4 "$TARGET/api/Challenges/" 2>/dev/null | python3 -c "import sys,json;print(sum(1 for c in json.load(sys.stdin).get('data',[]) if c.get('solved')))" 2>/dev/null || echo x)"
  [ "$n" = "0" ] && { log "target up (0 solved)"; break; }; sleep 2
done
log "[setup] governed seam"
python3 "$GB/governed_seam.py" open --target "$TARGET" --run-dir "$RUN" --ttl "${SEAM_TTL:-21600}" >>"$RUN/live.status" 2>&1 || { log "FATAL seam"; exit 1; }
log "[setup] mapping surface"
python3 "$GB/web_surface_mapper.py" --run-dir "$RUN" --max-fetch "${MAX_FETCH:-140}" >>"$RUN/map.log" 2>&1 || true
[ -f "$RUN/surface.json" ] && python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" >>"$RUN/map.log" 2>&1 || true
: > "$RUN/findings.jsonl"; echo "starting…" > "$LANE"
feeds --running
log "[setup] serving BattleStation 2.0 on :$PORT"
fuser -k "${PORT}/tcp" 2>/dev/null || true; sleep 1
BID="$(python3 -c "import json;print(json.load(open('$RUN/seam.json'))['battle'])")"
( export PYTHONPATH="$BS2:${PYTHONPATH:-}"; exec python3 -m battlestation.cli --db "$RUN/governed.sqlite3" --ariadne-url off serve --host 127.0.0.1 --port "$PORT" ) >>"$RUN/serve.log" 2>&1 &
SERVE_PID=$!
log "  -> http://127.0.0.1:$PORT  (battle $BID)"

# --- READ-ONLY watch loop (no DB writes; safe alongside any lane) ------------
rm -f "$DONE"
( while [ ! -f "$DONE" ]; do feeds --running; sleep 4; done ) &
WATCH_PID=$!

# --- LANE 1: governed sighted attacker --------------------------------------
echo "governed sighted attacker" > "$LANE"; log "[LANE 1] governed sighted attacker (${L1_MIN}m)"
cat > "$RUN/brief.md" <<EOF
You are the SIGHTED ATTACKER in a governed pentest of ${TARGET} (authorized, local, deliberately-vulnerable
OWASP Juice Shop). Time ~${L1_MIN} min. Every target-touching command goes THROUGH the 'gexec' shim (on PATH,
BS2_SEAM_RUN exported), never raw:
    GEXEC_CLASS=web.recon   gexec curl -s ${TARGET}/rest/products/search?q=test
    GEXEC_CLASS=web.exploit gexec curl -s -X POST ${TARGET}/rest/user/login -H 'Content-Type: application/json' --data '{...}'
Land footholds across classes (SQLi, auth/JWT, BAC/IDOR, NoSQLi, XSS). Ground truth: gexec curl -s ${TARGET}/api/Challenges/
Record EACH confirmed foothold immediately (the live panel reads these as they land):
    python3 ${GB}/governed_seam.py finding --run-dir ${RUN} --class <cls> --severity <sev> --work-id <wo-id> --label "<NON-SECRET, names the /path>"
    python3 ${GB}/governed_seam.py verify  --run-dir ${RUN} --work-id <wo-id>
Recon first, then breadth-first by class. Keep going until the clock runs out.
EOF
( cd "$RUN" && export BS2_SEAM_RUN="$RUN" PATH="$GB:$PATH"
  timeout "${L1_MIN}m" claude -p "$(cat "$RUN/brief.md")" --model "$MODEL" --dangerously-skip-permissions \
    --max-turns "${MAXTURNS:-250}" --append-system-prompt "Governed pentest operator: every target-touching command via gexec. Record each finding immediately." >>"$RUN/attacker.log" 2>&1 )
log "[LANE 1] done — promote"; promote

# --- LANE 2: L2 expert dispatch (top-3 specialists, NOT the deep L3) ---------
echo "L2 experts · sqli+auth-bypass+bac" > "$LANE"; log "[LANE 2] L2 expert dispatch (${L2_MIN}m cap)"
python3 "$GB/dispatch.py" level 2 >/dev/null 2>&1 || true
python3 "$GB/dispatch.py" arm   >/dev/null 2>&1 || true
timeout "${L2_MIN}m" python3 "$GB/dispatch.py" run --run-dir "$RUN" >>"$RUN/dispatch.log" 2>&1 || true
python3 "$GB/dispatch.py" disarm >/dev/null 2>&1 || true
log "[LANE 2] done — promote"; promote

# --- LANE 3: AUTOTURRET recipe-spray (own War Room + own UI port) ------------
echo "autoturret recipe-spray" > "$LANE"; log "[LANE 3] AUTOTURRET at ${TARGET} (${L3_MIN}m, own War Room)"
( timeout "${L3_MIN}m" bash "$GB/run_double_barrel.sh" "$TARGET" "$L3_MIN" >>"$RUN/autoturret.log" 2>&1 ) &
AT_PID=$!
ATPORT="$(grep -oE 'UI.*:[0-9]{4,5}' "$RUN/autoturret.log" 2>/dev/null | grep -oE '[0-9]{4,5}' | head -1)"
wait "$AT_PID" 2>/dev/null
log "[LANE 3] autoturret ended (see $RUN/autoturret.log for its War Room port)"

# --- WRAP UP -----------------------------------------------------------------
echo "relay complete" > "$LANE"; touch "$DONE"; wait "$WATCH_PID" 2>/dev/null
promote; feeds
AFTER="$(curl -s --max-time 6 "$TARGET/api/Challenges/" 2>/dev/null | python3 -c "import sys,json;print(sum(1 for c in json.load(sys.stdin).get('data',[]) if c.get('solved')))" 2>/dev/null || echo n/a)"
NF="$(wc -l < "$RUN/findings.jsonl" 2>/dev/null || echo 0)"
log "RELAY DONE. governed findings=$NF · scoreboard solved=$AFTER · page live on :$PORT"
