#!/usr/bin/env bash
# =============================================================================
# run_engagement — the SINGLE leveled entrypoint (Laketree deliverable).
# Sequences the whole governed spine, driven by ONE level dial:
#
#   open(seam) -> MAP(route: appmap|hostmap|both) -> PLAN(Ariadne) ->
#   DISPATCH(level: recipes and/or experts, via gexec) -> GOVERN(warroom/ledger) -> TALLY
#
# Nothing spends at L0 (map-only) or while dispatch is DISARMED.
#
# Usage:  run_engagement.sh <TARGET> [RUN_DIR]
#   env   LEVEL=0|1|2|3 (default 0)   MAP=appmap|hostmap|both (default auto)   ARM=1 to arm
# =============================================================================
set -uo pipefail
GB=/opt/bs2/live
TARGET="${1:?usage: run_engagement.sh <TARGET> [RUN_DIR]}"
SLUG="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9' '_' | sed 's/__*/_/g;s/^_//;s/_$//')"
RUN="${2:-$GB/engagements/$SLUG}"
LEVEL="${LEVEL:-0}"
mkdir -p "$RUN"
log(){ echo "$(date +%H:%M:%S) $*" | tee -a "$RUN/engagement.status"; }

# --- route the MAP stage by target shape (unless MAP is forced) ---
route(){
  if [ -n "${MAP:-}" ]; then echo "$MAP"; return; fi
  case "$TARGET" in
    http://*|https://*) echo "appmap" ;;                 # a URL -> application surface
    */*|*[0-9].*[0-9]/*) echo "hostmap" ;;               # a CIDR -> host recon
    *) echo "appmap" ;;                                  # bare host: default appmap (add hostmap w/ MAP=both)
  esac
}
MAPMODE="$(route)"

log "=== ENGAGEMENT  target=$TARGET  level=L$LEVEL  map=$MAPMODE  run=$RUN ==="

# --- 1) open governed seam ---
log "[1/5] open governed seam"
python3 "$GB/governed_seam.py" open --target "$TARGET" --run-dir "$RUN" --ttl "${SEAM_TTL:-21600}" \
  >> "$RUN/engagement.status" 2>&1 || { log "FATAL seam open"; exit 1; }

# --- 2) MAP ---
log "[2/5] MAP ($MAPMODE)"
case "$MAPMODE" in
  appmap|both)
    python3 "$GB/web_surface_mapper.py" --run-dir "$RUN" --max-fetch "${MAX_FETCH:-140}" 2>>"$RUN/map.log" | tee -a "$RUN/engagement.status"
    # project the application-surface MAP into the governed graph so the green
    # BattleStation 2.0 page renders it (map of the box, content-blind).
    if [ -f "$RUN/surface.json" ]; then
      python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" 2>>"$RUN/map.log" | tee -a "$RUN/engagement.status"
    fi ;;
esac
if [ "$MAPMODE" = "hostmap" ] || [ "$MAPMODE" = "both" ]; then
  log "hostmap lane: hand off to recipe engine's recon (run_double_barrel) — not auto-run here"
fi

# --- 3) PLAN — performed inside the mapper (Ariadne /plan per class); surfaced here ---
if [ -f "$RUN/worklist.json" ]; then
  N=$(python3 -c "import json;print(len(json.load(open('$RUN/worklist.json'))))" 2>/dev/null || echo 0)
  log "[3/5] PLAN: worklist has $N per-class items (Ariadne paths in plans.json)"
else
  log "[3/5] PLAN: no worklist (hostmap-only or map produced none)"
fi

# --- 4) DISPATCH by level ---
log "[4/5] DISPATCH (level L$LEVEL)"
python3 "$GB/dispatch.py" level "$LEVEL" >/dev/null 2>&1 || true
[ "${ARM:-0}" = "1" ] && python3 "$GB/dispatch.py" arm >/dev/null 2>&1 || true
case "$LEVEL" in
  0) log "L0 map-only — no dispatch. Review: surface.json / worklist.json"; python3 "$GB/dispatch.py" plan --run-dir "$RUN" | tee -a "$RUN/engagement.status" ;;
  1) log "L1 LIGHT — recipe lane. Launch: $GB/run_double_barrel.sh $TARGET"; ;;
  2|3)
     python3 "$GB/dispatch.py" plan --run-dir "$RUN" | tee -a "$RUN/engagement.status"
     if [ "${ARM:-0}" = "1" ]; then
       log "ARMED — dispatching experts"
       python3 "$GB/dispatch.py" run --run-dir "$RUN" | tee -a "$RUN/engagement.status"
     else
       log "DISARMED — dry plan only. Re-run with ARM=1 (or: dispatch arm; dispatch run --run-dir $RUN) to spend."
     fi ;;
esac

# --- 4b) PROMOTE: turn mapped fog nodes OWNED where findings proved them (graph goes green) ---
if [ -f "$RUN/surface.json" ] && [ -f "$RUN/findings.jsonl" ]; then
  log "PROMOTE: binding findings to surface nodes"
  python3 "$GB/surface_to_terrain.py" --run-dir "$RUN" --promote 2>>"$RUN/map.log" | tee -a "$RUN/engagement.status"
fi

# --- 5) GOVERN + TALLY ---
log "[5/5] GOVERN/TALLY"
python3 "$GB/governed_seam.py" status --run-dir "$RUN" 2>/dev/null | tee -a "$RUN/engagement.status" || true
log "artifacts in $RUN : surface.json worklist.json plans.json ariadne_facts.jsonl  (+ experts/ if armed)"
log "VIEW (green BattleStation 2.0):  $GB/serve_governed.sh $RUN   # then open http://127.0.0.1:8126"
