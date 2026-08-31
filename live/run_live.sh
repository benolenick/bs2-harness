#!/usr/bin/env bash
# =============================================================================
# run_live — fresh juice-shop, governed attack, LIVE-updating BattleStation 2.0.
#
# Resets the target, opens a governed seam, maps the surface (fog nodes appear),
# launches the delegated sighted attacker (claude -p, all target-touching cmds
# through gexec), and runs a watch loop that (a) regenerates intake.json so the
# LEFT "Live intake" panel fills as findings actually land, and (b) promotes
# proven nodes so the MAP greens up — all while you watch http://127.0.0.1:8126.
#
#   run_live.sh [TARGET] [MINUTES]
#     env  CONTAINER=juice-bs2-wb  PORT=8126  MODEL=claude-sonnet-5
# =============================================================================
set -uo pipefail
GB=/opt/bs2/live
BS2=/mnt/sata/htb-bakeoff/bs2-governed-wt
STATIC1="$BS2/battlestation/static/intake.json"
STATIC2="/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/static/intake.json"
TARGET="${1:-http://127.0.0.1:3060}"
MIN="${2:-20}"
CONTAINER="${CONTAINER:-juice-bs2-wb}"
PORT="${PORT:-8126}"
MODEL="${MODEL:-claude-sonnet-5}"
RUN="$GB/engagements/live_$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9' '_' | sed 's/__*/_/g;s/^_//;s/_$//')"
STOP="$RUN/STOP"
log(){ echo "$(date +%H:%M:%S) $*" | tee -a "$RUN/live.status"; }

rm -rf "$RUN"; mkdir -p "$RUN"

# --- 1) FRESH juice-shop (restart wipes in-memory challenge state) -----------
log "[1/6] resetting target container $CONTAINER (fresh board)"
docker restart "$CONTAINER" >/dev/null 2>&1 || { log "FATAL: docker restart $CONTAINER"; exit 1; }
for i in $(seq 1 40); do
  n="$(curl -s --max-time 4 "$TARGET/api/Challenges/" 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin).get('data',[]);print(sum(1 for c in d if c.get('solved')))" 2>/dev/null || echo x)"
  [ "$n" = "0" ] && { log "target up, scoreboard=0 solved"; break; }
  sleep 2
done

# --- 2) governed seam --------------------------------------------------------
log "[2/6] opening governed seam"
python3 "$GB/governed_seam.py" open --target "$TARGET" --run-dir "$RUN" --ttl "${SEAM_TTL:-21600}" \
  >> "$RUN/live.status" 2>&1 || { log "FATAL seam open"; exit 1; }

# --- 3) MAP the surface (fog nodes) -----------------------------------------
log "[3/6] mapping application surface"
python3 "$GB/web_surface_mapper.py" --run-dir "$RUN" --max-fetch "${MAX_FETCH:-140}" >>"$RUN/map.log" 2>&1 || true
if [ -f "$RUN/surface.json" ]; then
  python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" >>"$RUN/map.log" 2>&1 || true
fi
: > "$RUN/findings.jsonl"   # start empty so the panel fills from zero
python3 "$GB/intake_feed.py" --run-dir "$RUN" --live --running --out "$STATIC1" --out "$STATIC2" >/dev/null
MGR1="$BS2/battlestation/static/manager.json"
MGR2="/mnt/acer/your-host-offload/Desktop/HTB/battlestation-v2/battlestation/static/manager.json"
python3 "$GB/manager_feed.py" --run-dir "$RUN" --running --out "$MGR1" --out "$MGR2" >/dev/null 2>&1 || true

# --- 4) serve the live page --------------------------------------------------
log "[4/6] serving BattleStation 2.0 on :$PORT"
fuser -k "${PORT}/tcp" 2>/dev/null || true; sleep 1
BID="$(python3 -c "import json;print(json.load(open('$RUN/seam.json'))['battle'])")"
( export PYTHONPATH="$BS2:${PYTHONPATH:-}"
  exec python3 -m battlestation.cli --db "$RUN/governed.sqlite3" --ariadne-url off serve \
       --host 127.0.0.1 --port "$PORT" ) >>"$RUN/serve.log" 2>&1 &
SERVE_PID=$!
log "  -> http://127.0.0.1:$PORT  (battle $BID)"

# --- 5) delegated sighted attacker (writes findings.jsonl as it lands) -------
cat > "$RUN/brief.md" <<EOF
You are the SIGHTED ATTACKER in a governed pentest of ${TARGET} (authorized, local,
deliberately-vulnerable OWASP Juice Shop — no real data). Time budget ~${MIN} min.
Non-destructive, strictly this one target.

HARD RULE — every command that TOUCHES THE TARGET runs THROUGH the governed seam via the
'gexec' shim (already on PATH; BS2_SEAM_RUN is exported), never raw:
    GEXEC_CLASS=web.recon   gexec curl -s ${TARGET}/rest/products/search?q=test
    GEXEC_CLASS=web.exploit gexec curl -s -X POST ${TARGET}/rest/user/login -H 'Content-Type: application/json' --data '{...}'
You SEE raw output; the action becomes a governed event; local tooling (jq/python/files) is normal bash.

OBJECTIVE: land confirmed footholds across as many classes as you can — SQLi, broken auth/JWT,
broken access control/IDOR, NoSQLi, XSS, path traversal, sensitive-data exposure. Ground truth:
    gexec curl -s ${TARGET}/api/Challenges/   # each item has boolean "solved"

AFTER EACH CONFIRMED FOOTHOLD, record it immediately (do NOT batch — the live panel reads these
as they land) as governed evidence:
    python3 ${GB}/governed_seam.py finding --run-dir ${RUN} --class <sqli|nosqli|auth|bac|xss|path-traversal|auth-bypass> \\
        --severity <low|medium|high|critical> --work-id <the wo-id gexec printed> \\
        --label "<short NON-SECRET description that names the /path>"
    python3 ${GB}/governed_seam.py verify --run-dir ${RUN} --work-id <wo-id>
Keep labels free of secret values, but DO name the endpoint path (the panel/map bind on it).
Begin with recon, then attack breadth-first by class. Record each foothold the moment it lands.
Do NOT stop after a handful — OWASP Juice Shop has 100+ challenges. Keep going breadth-first across
EVERY class, re-checking the scoreboard, pivoting to unsolved items, until the clock runs out.
Aim for 15+ distinct confirmed findings. Each new finding lights up the live panel — keep them coming.
EOF

log "[5/6] launching delegated attacker (model=$MODEL, ${MIN}m)"
SYS="You are a governed pentest operator. Every target-touching command MUST go through 'gexec' (never raw). Authorized for this single local target only. Record each confirmed finding immediately."
( cd "$RUN" && export BS2_SEAM_RUN="$RUN" PATH="$GB:$PATH"
  timeout "${MIN}m" claude -p "$(cat "$RUN/brief.md")" --model "$MODEL" \
    --dangerously-skip-permissions --max-turns "${MAXTURNS:-300}" \
    --append-system-prompt "$SYS" >>"$RUN/attacker.log" 2>&1 ) &
ATT_PID=$!
log "  attacker pid $ATT_PID"

# --- 6) LIVE watch loop: refresh intake + promote while the attack runs ------
log "[6/6] live loop running — watch http://127.0.0.1:$PORT (Ctrl-C or 'touch $STOP' to stop)"
while kill -0 "$ATT_PID" 2>/dev/null; do
  [ -f "$STOP" ] && { log "STOP requested"; kill "$ATT_PID" 2>/dev/null; break; }
  python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" --promote >>"$RUN/map.log" 2>&1 || true
  python3 "$GB/intake_feed.py" --run-dir "$RUN" --live --running --out "$STATIC1" --out "$STATIC2" >/dev/null 2>&1 || true
  python3 "$GB/manager_feed.py" --run-dir "$RUN" --running --out "$MGR1" --out "$MGR2" >/dev/null 2>&1 || true
  sleep 4
done
wait "$ATT_PID" 2>/dev/null
log "attacker ended — final promote + intake refresh"
python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" --promote >>"$RUN/map.log" 2>&1 || true
python3 "$GB/intake_feed.py" --run-dir "$RUN" --live --out "$STATIC1" --out "$STATIC2" >/dev/null 2>&1 || true
python3 "$GB/manager_feed.py" --run-dir "$RUN" --out "$MGR1" --out "$MGR2" >/dev/null 2>&1 || true
AFTER="$(curl -s --max-time 6 "$TARGET/api/Challenges/" 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin).get('data',[]);print(sum(1 for c in d if c.get('solved')))" 2>/dev/null || echo n/a)"
NF="$(wc -l < "$RUN/findings.jsonl" 2>/dev/null || echo 0)"
log "DONE. findings=$NF · scoreboard solved=$AFTER · page still live on :$PORT (serve pid $SERVE_PID)"
