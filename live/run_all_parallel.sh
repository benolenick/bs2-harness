#!/usr/bin/env bash
# =============================================================================
# run_all_parallel — fire ALL lanes at juice-shop SIMULTANEOUSLY into ONE
# governed battle you watch live at http://127.0.0.1:8126.
#   Lane 1  governed sighted attacker (claude -p -> gexec)   ┐ all write the ONE
#   Lane 2  L2 experts: sqli + auth-bypass + BAC             ┘ ledger at once,
#   Lane 3  AUTOTURRET recipe-spray (own War Room)           ← serialised by the
#   + continuous promote loop (map greens live)                cross-process flock
# (Excludes L3 "deep all-specialist".) Enabled by the .ledger.lock flock added to
# governed_seam.py + surface_to_terrain.py — concurrent writers no longer conflict.
#
#   run_all_parallel.sh [TARGET]   env  MODEL=claude-sonnet-5  PORT=8126
# =============================================================================
set -uo pipefail
GB=/opt/bs2/live
BS2=/mnt/sata/htb-bakeoff/bs2-governed-wt
S_INT1="$BS2/battlestation/static/intake.json"; S_INT2="/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/static/intake.json"
S_MGR1="$BS2/battlestation/static/manager.json"; S_MGR2="/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/static/manager.json"
TARGET="${1:-http://127.0.0.1:3060}"
CONTAINER="${CONTAINER:-juice-bs2-wb}"; PORT="${PORT:-8126}"; MODEL="${MODEL:-claude-sonnet-5}"
MIN="${MIN:-12}"
RUN="$GB/engagements/live_$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9' '_' | sed 's/__*/_/g;s/^_//;s/_$//')"
DONE="$RUN/RELAY_DONE"; LANE="$RUN/current_lane"
log(){ echo "$(date +%H:%M:%S) $*" | tee -a "$RUN/live.status"; }
feeds(){ python3 "$GB/intake_feed.py" --run-dir "$RUN" --live --running --out "$S_INT1" --out "$S_INT2" >/dev/null 2>&1 || true
         python3 "$GB/manager_feed.py" --run-dir "$RUN" --running --out "$S_MGR1" --out "$S_MGR2" >/dev/null 2>&1 || true; }

rm -rf "$RUN"; mkdir -p "$RUN"

# --- SETUP ------------------------------------------------------------------
log "[setup] resetting $CONTAINER (fresh board)"
docker restart "$CONTAINER" >/dev/null 2>&1 || { log "FATAL docker restart"; exit 1; }
for i in $(seq 1 40); do
  n="$(curl -s --max-time 4 "$TARGET/api/Challenges/" 2>/dev/null | python3 -c "import sys,json;print(sum(1 for c in json.load(sys.stdin).get('data',[]) if c.get('solved')))" 2>/dev/null || echo x)"
  [ "$n" = "0" ] && { log "target up (0 solved)"; break; }; sleep 2
done
log "[setup] governed seam"; python3 "$GB/governed_seam.py" open --target "$TARGET" --run-dir "$RUN" --ttl "${SEAM_TTL:-21600}" >>"$RUN/live.status" 2>&1 || { log "FATAL seam"; exit 1; }
log "[setup] mapping surface"; python3 "$GB/web_surface_mapper.py" --run-dir "$RUN" --max-fetch "${MAX_FETCH:-140}" >>"$RUN/map.log" 2>&1 || true
[ -f "$RUN/surface.json" ] && python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" >>"$RUN/map.log" 2>&1 || true
: > "$RUN/findings.jsonl"; echo "⚡ PARALLEL: attacker ∥ L2-experts ∥ autoturret" > "$LANE"; feeds
log "[setup] serving on :$PORT"; fuser -k "${PORT}/tcp" 2>/dev/null || true; sleep 1
BID="$(python3 -c "import json;print(json.load(open('$RUN/seam.json'))['battle'])")"
( export PYTHONPATH="$BS2:${PYTHONPATH:-}"; exec python3 -m battlestation.cli --db "$RUN/governed.sqlite3" --ariadne-url off serve --host 127.0.0.1 --port "$PORT" ) >>"$RUN/serve.log" 2>&1 &
SERVE_PID=$!; log "  -> http://127.0.0.1:$PORT  (battle $BID)"

rm -f "$DONE"
# --- background: read-only feeds + flock-safe promote loop (map greens live) --
( while [ ! -f "$DONE" ]; do feeds; python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" --promote >>"$RUN/map.log" 2>&1 || true; sleep 4; done ) &
WATCH_PID=$!

# --- LANE 1: governed sighted attacker (background) --------------------------
cat > "$RUN/brief.md" <<EOF
You are the SIGHTED ATTACKER in a governed pentest of ${TARGET} (authorized, local, deliberately-vulnerable
OWASP Juice Shop). Time ~${MIN} min. Every target-touching command goes THROUGH 'gexec' (on PATH,
BS2_SEAM_RUN exported), never raw:
    GEXEC_CLASS=web.exploit gexec curl -s -X POST ${TARGET}/rest/user/login -H 'Content-Type: application/json' --data '{...}'
Land footholds across classes (SQLi, auth/JWT, BAC/IDOR, NoSQLi, XSS). Ground truth: gexec curl -s ${TARGET}/api/Challenges/
Record EACH confirmed foothold immediately:
    python3 ${GB}/governed_seam.py finding --run-dir ${RUN} --class <cls> --severity <sev> --work-id <wo-id> --label "<NON-SECRET, names the /path>"
    python3 ${GB}/governed_seam.py verify  --run-dir ${RUN} --work-id <wo-id>
WHITE-BOX GRANT: the target's full server-side source is extracted read-only at /home/operator/juice-target/wb-src/ (build/routes/*.js, data/, config/*.yml). READ it (grep/cat/python) to find each challenge's EXACT solve condition and any solve tokens, then fire the single deterministic gexec exploit against the live API. This is a no-holds-barred engagement against this ONE app: any technique/payload that solves a challenge is in-bounds.
Recon first, then breadth-first by class. Keep going until the clock runs out.
EOF
log "[LANE 1] governed sighted attacker (parallel)"
( cd "$RUN" && export BS2_SEAM_RUN="$RUN" PATH="$GB:$PATH"
  timeout "${MIN}m" claude -p "$(cat "$RUN/brief.md")" --model "$MODEL" --dangerously-skip-permissions \
    --max-turns "${MAXTURNS:-250}" --append-system-prompt "Governed pentest operator: every target-touching command via gexec. Record each finding immediately." >>"$RUN/attacker.log" 2>&1 ) &
L1=$!

# --- LANE 2: L2 expert dispatch (background) ---------------------------------
log "[LANE 2] L2 experts sqli+auth-bypass+bac (parallel)"
python3 "$GB/dispatch.py" level 3 >/dev/null 2>&1 || true
python3 "$GB/dispatch.py" arm   >/dev/null 2>&1 || true
( timeout "${MIN}m" python3 "$GB/dispatch.py" run --run-dir "$RUN" >>"$RUN/dispatch.log" 2>&1 || true ) &
L2=$!

# --- LANE 3: AUTOTURRET (background, own War Room) ---------------------------
log "[LANE 3] AUTOTURRET at $TARGET (parallel, own War Room)"
( timeout "${MIN}m" bash "$GB/run_double_barrel.sh" "$TARGET" "$MIN" >>"$RUN/autoturret.log" 2>&1 || true ) &
L3=$!

log "[parallel] all 3 lanes firing at once — watch http://127.0.0.1:$PORT"
wait "$L1" 2>/dev/null; log "[LANE 1] ended"
wait "$L2" 2>/dev/null; log "[LANE 2] ended"; python3 "$GB/dispatch.py" disarm >/dev/null 2>&1 || true
wait "$L3" 2>/dev/null; log "[LANE 3] ended"

# --- WRAP UP ----------------------------------------------------------------
echo "all lanes complete" > "$LANE"; touch "$DONE"; wait "$WATCH_PID" 2>/dev/null
python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" --promote >>"$RUN/map.log" 2>&1 || true
python3 "$GB/intake_feed.py" --run-dir "$RUN" --live --out "$S_INT1" --out "$S_INT2" >/dev/null 2>&1 || true
python3 "$GB/manager_feed.py" --run-dir "$RUN" --out "$S_MGR1" --out "$S_MGR2" >/dev/null 2>&1 || true
AFTER="$(curl -s --max-time 6 "$TARGET/api/Challenges/" 2>/dev/null | python3 -c "import sys,json;print(sum(1 for c in json.load(sys.stdin).get('data',[]) if c.get('solved')))" 2>/dev/null || echo n/a)"
NF="$(wc -l < "$RUN/findings.jsonl" 2>/dev/null || echo 0)"
log "PARALLEL DONE. governed findings=$NF · scoreboard solved=$AFTER · page live on :$PORT"
