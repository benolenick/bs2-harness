#!/usr/bin/env bash
# =============================================================================
# DOUBLE BARREL — full BS2 suite (governed ledger + Ariadne + Memoria RAG +
# escalation ladder + live War Room UI + penalty tracker) driving the
# FLASH-AUTOTURRET trooper instead of Opus claude-p hands.
#
#   Barrel 1: autoturret engine — catalog cards + Ariadne planner (/plan, CVE leads)
#   Barrel 2: Memoria RAG hints fed straight to the deepseek-flash trooper
#   Manager : the human-facing Claude session (content-blind; reads scrubbed feed + map)
#   Bridge  : autoturret grounded facts -> bs2_emit -> map.json -> War Room
#
# Usage:  run_double_barrel.sh <TARGET_IP> [RUN_MINUTES]
# =============================================================================
set -uo pipefail
GB=/opt/bs2/live
CODE=/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria     # code + static assets (warroom/ladder/etc)
BS2=/mnt/sata/htb-bakeoff/bs2-governed-wt               # governed core (setup_battle imports it)
TARGET="${1:?usage: run_double_barrel.sh <TARGET> [RUN_MINUTES]   (TARGET = IP or URL)}"
RUN_MINUTES="${2:-${RUN_MINUTES:-90}}"

# --- per-target run isolation: each target gets its own state dir + UI port so a new
#     run never clobbers or kills a live one. Override with RUN_TAG / RUN_DIR / UIPORT.
SLUG="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9' '_' | sed 's/__*/_/g; s/^_//; s/_$//')"
RUN_TAG="${RUN_TAG:-$SLUG}"
DIR="${RUN_DIR:-$CODE/runs/$RUN_TAG}"                    # BS2 state: map/telemetry/escalation/UI
ATRUN=$DIR/atrun                                         # autoturret's own run dir
export BS2_RUN_DIR="$DIR"                                # warroom/ladder/setup_battle read this
mkdir -p "$DIR"
if [ -z "${UIPORT:-}" ]; then                           # deterministic per-target UI port
  _h=$(printf '%s' "$RUN_TAG" | cksum | cut -d' ' -f1)
  UIPORT=$(( 8141 + (_h % 50) ))
fi
ATTACKER="${ATTACKER:-10.10.14.153}"
AT_TTL="${AT_TTL:-1500}"                                 # per-iteration autoturret TTL
DEADLINE=$(( $(date +%s) + RUN_MINUTES*60 ))

echo "$(date +%H:%M:%S) === DOUBLE BARREL launching (target=$TARGET, +${RUN_MINUTES}m, ui=:$UIPORT) ===" | tee -a "$DIR/run.status"

# --- fresh run state --------------------------------------------------------
rm -f "$DIR/armB.done" "$DIR/telemetry.json" "$DIR/STRATEGY.md" "$DIR/ariadne_facts.jsonl" \
      "$DIR/stream.jsonl" "$DIR/CAPTURED" "$DIR/escalation.json"
for x in campaign.sqlite3 campaign.sqlite3-wal campaign.sqlite3-shm; do rm -f "$DIR/$x"; done
rm -rf "$DIR/campaign.sqlite3.witness" "$ATRUN"; mkdir -p "$ATRUN"
echo "{\"hosts\":[{\"ip\":\"$TARGET\",\"role\":\"external-perimeter\",\"owned\":false,\"state\":\"spotted\",\"services\":[]}],\"creds\":[],\"flags\":[],\"pivots\":[],\"edges\":[],\"frontier\":[\"enumerate $TARGET\"],\"updated\":0}" > "$DIR/map.json"
echo "{\"arm\":\"double-barrel\",\"phase\":\"starting\",\"ts\":$(date +%s),\"hosts_owned\":[],\"hosts_discovered\":[\"$TARGET\"],\"hops\":0,\"flags\":[]}" > "$DIR/telemetry.json"
: > "$DIR/ariadne_facts.jsonl"; echo "# double-barrel bootstrapping" > "$DIR/STRATEGY.md"
export TELEMETRY="$DIR/telemetry.json"

# --- governed battle ledger (BS2 core) --------------------------------------
# The charter wants a HOST selector, not a URL — strip scheme/port/path so a URL target
# (web app) still produces a valid governed ledger while autoturret keeps the full URL.
HOST="$(printf '%s' "$TARGET" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')"
( cd "$BS2" && PYTHONPATH="$BS2" python3 "$CODE/setup_battle.py" "$HOST" ) \
  >> "$DIR/run.status" 2>&1 && echo "$(date +%H:%M:%S) governed ledger created" >> "$DIR/run.status" \
  || echo "$(date +%H:%M:%S) WARN: setup_battle failed (map still drives UI)" >> "$DIR/run.status"

# --- live War Room UI -------------------------------------------------------
pkill -f "warroom.py --port $UIPORT" 2>/dev/null || true
( cd "$DIR" && nohup python3 "$CODE/warroom.py" --port "$UIPORT" >> "$DIR/warroom.log" 2>&1 & )
echo "$(date +%H:%M:%S) War Room UI -> http://127.0.0.1:$UIPORT" >> "$DIR/run.status"

# --- escalation ladder: content-blind supervisor -> escalation.json (UI lens)
pkill -f "escalation_ladder.py --rundir $DIR" 2>/dev/null || true
( cd "$DIR" && BS2_LADDER_NO_OPERATOR="${BS2_LADDER_NO_OPERATOR:-1}" BS2_LADDER_SECOND_OPINION="${BS2_LADDER_SECOND_OPINION:-0}" \
    BS2_LADDER_RESEARCH="${BS2_LADDER_RESEARCH:-1}" PENTEST_RAG="${PENTEST_RAG:-}" \
    nohup python3 "$CODE/escalation_ladder.py" --rundir "$DIR" >> "$DIR/escalation.log" 2>&1 & )
echo "$(date +%H:%M:%S) escalation ladder started" >> "$DIR/run.status"

# --- penalty tracker (hands back API-throttle time) -------------------------
rm -f "$DIR/penalty.json" "$DIR/.penalty_offsets.json"
( cd "$DIR" && nohup python3 "$CODE/penalty_tracker.py" watch --dir "$DIR" \
    --cooldown "${PENALTY_COOLDOWN:-45}" --poll 5 >> "$DIR/penalty.log" 2>&1 & )
DEADLINE_BASE=$DEADLINE
echo "$(date +%H:%M:%S) penalty tracker started" >> "$DIR/run.status"

# --- resolver auto-provision: keep /etc/hosts synced with discovered vhosts ----------
# (the engine does the zone transfer, so it knows every vhost; without this, manually
#  dispatched troopers die at DNS. idempotent managed block; needs NOPASSWD sudo.)
( while kill -0 $$ 2>/dev/null; do sudo -n python3 "$GB/vhost_sync.py" --target "$TARGET" --run-dir "$ATRUN" >/dev/null 2>&1; sleep 30; done ) &
echo "$(date +%H:%M:%S) vhost_sync resolver provisioner started" >> "$DIR/run.status"

# --- autoturret -> war-room bridge (content-tier) ---------------------------
pkill -f "autoturret_bs2_bridge.py $ATRUN" 2>/dev/null || true
( AUTOTURRET_RUN="$ATRUN" GB_TARGET="$TARGET" TELEMETRY="$DIR/telemetry.json" \
  BS2_MAP="$DIR/map.json" \
  nohup python3 "$GB/autoturret_bs2_bridge.py" "$ATRUN" "$TARGET" >> "$DIR/bridge.log" 2>&1 & )
echo "$(date +%H:%M:%S) autoturret->BS2 bridge started" >> "$DIR/run.status"

# --- flash-autoturret HANDS loop: run to deadline, re-plan when frontier dries
export AUTOTURRET_CATALOG=1 GB_CATALOG=/opt/bs2/catalog/deck_run.yaml GB_JUDGE=1
# authorized local training targets live on loopback (juice-shop) — let the scope-guard permit
# loopback ONLY for a loopback target (HTB/10.129 runs never match, so they keep the hard deny).
case "$TARGET" in *127.0.0.1*|*localhost*) export GB_ALLOW_LOOPBACK=1 ;; esac
export GB_LHOST="$ATTACKER" GB_ARIADNE=http://127.0.0.1:8112
export GB_MEMORIA_SSH="${GB_MEMORIA_SSH:-your-host}" GB_MEMORIA_URL="${GB_MEMORIA_URL:-http://127.0.0.1:8009/search}"
export GB_KNOWLEDGE=1
export GB_MANAGER_DIRECTIVES="$ATRUN/manager_directives.md"   # LEVER 3: manager->trooper abstract directives
export TROOPER_BASE=https://api.deepseek.com TROOPER_MODEL=deepseek-v4-flash
export TROOPER_KEY_FILE=/opt/bs2/.ds_key TROOPER_MAX_TOKENS=3000 TROOPER_CMD_TIMEOUT=40
unset TROOPER_EXEC_SSH                                   # target reachable from your-host tun0

attempt=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  PEN=$(python3 "$CODE/penalty_tracker.py" total --dir "$DIR" 2>/dev/null || echo 0)
  DEADLINE=$(( DEADLINE_BASE + ${PEN:-0} ))
  [ -f "$DIR/CAPTURED" ] && { echo "$(date +%H:%M:%S) CAPTURED — clean stop" >> "$DIR/run.status"; break; }
  # owned? clean stop
  if python3 -c "import json,sys; d=json.load(open('$ATRUN/recon.json')); sys.exit(0 if d.get('owned') else 1)" 2>/dev/null; then
    echo "$(date +%H:%M:%S) OWNED — clean stop" >> "$DIR/run.status"; touch "$DIR/CAPTURED"; break
  fi
  # LEVER 1 — manager HOLD: if the manager is reconfiguring (dropped atrun/hold), pause sweeps
  # instead of blindly re-firing. Absent = normal. This is the "time and place to fire" control.
  if [ -f "$ATRUN/hold" ]; then
    echo "$(date +%H:%M:%S) HELD by manager (atrun/hold present) — waiting" >> "$DIR/run.status"
    sleep 15; continue
  fi
  attempt=$((attempt+1))
  # remaining seconds -> this iteration's TTL (min of AT_TTL and time left)
  now=$(date +%s); left=$(( DEADLINE - now )); [ "$left" -lt 60 ] && break
  ttl=$AT_TTL; [ "$ttl" -gt "$left" ] && ttl=$left
  # LEVER 1 (cont) — fact-delta: log when a sweep runs on an UNCHANGED fact-set (redundant),
  # so the manager sees when to switch levers (reset goal / add directive) vs let it spin.
  FSIG=$(python3 -c "import json;d=json.load(open('$ATRUN/recon.json'));print(len(d.get('proven_facts') or []))" 2>/dev/null || echo 0)
  if [ "${FSIG:-0}" = "${LAST_FSIG:-x}" ]; then
    echo "$(date +%H:%M:%S) NOTE: no new facts since last sweep (proven=$FSIG) — consider resetting goal/directives" >> "$DIR/run.status"
  fi
  LAST_FSIG=$FSIG
  # LEVER 2 — resettable planner goal: manager writes atrun/planner_goal (e.g. 'rce_as:drupal',
  # 'root', 'read_file:/etc/passwd', 'rce'); next sweep picks it up. Default 'rce' = prior behaviour.
  PLAN=$(cat "$ATRUN/planner_goal" 2>/dev/null | tr -d '[:space:]'); PLAN="${PLAN:-rce}"
  echo "$(date +%H:%M:%S) autoturret attempt=$attempt ttl=${ttl}s goal=$PLAN" >> "$DIR/run.status"
  start=$(date +%s)
  ( cd "$GB" && AUTOTURRET_RUN="$ATRUN" AUTOTURRET_TTL="$ttl" \
      python3 autoturret.py --target "$TARGET" --dial full --planner "$PLAN" \
        --run-dir "$ATRUN" --ttl "$ttl" >> "$DIR/autoturret.iter.log" 2>&1 )
  dur=$(( $(date +%s) - start ))
  echo "$(date +%H:%M:%S) autoturret attempt=$attempt done dur=${dur}s" >> "$DIR/run.status"
  # anti-spin backoff if it died instantly
  [ "$dur" -lt 20 ] && sleep 10 || sleep 3
done

touch "$DIR/armB.done"
PEN=$(python3 "$CODE/penalty_tracker.py" total --dir "$DIR" 2>/dev/null || echo 0)
echo "$(date +%H:%M:%S) DOUBLE BARREL COMPLETE (attempts=$attempt); throttle handed back=${PEN}s" >> "$DIR/run.status"
# leave UI + bridge running so final state stays watchable
pkill -f "escalation_ladder.py --rundir $DIR" 2>/dev/null || true
pkill -f "penalty_tracker.py watch --dir $DIR" 2>/dev/null || true
