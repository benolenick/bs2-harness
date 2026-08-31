#!/usr/bin/env bash
# Detect trooper guardrail-failure: a refusing Sonnet leaves NO governed footprint.
RUN="${1:?run-dir}"; BASE="${2:-0}"
DB="$RUN/governed.sqlite3"
now=$(sqlite3 "$DB" "SELECT count(*) FROM battle_events;" 2>/dev/null)
disp=$(sqlite3 "$DB" "SELECT count(*) FROM battle_events WHERE event_type='tool.dispatched';" 2>/dev/null)
echo "== trooper audit =="
echo "  ledger events: $BASE -> $now   (delta $((now-BASE)))"
echo "  governed dispatches total: $disp"
echo "  findings recorded:"
python3 /opt/bs2/live/governed_seam.py events --run-dir "$RUN" 2>/dev/null | grep -i "finding\|proof" | head
if [ "$((now-BASE))" -le 0 ]; then
  echo "  !! ZERO new governed actions since baseline — troopers likely refused at a guardrail or crashed."
  command -v ping-ben >/dev/null && ping-ben --title "BS2" --priority high "crAPI troopers left NO governed footprint — likely guardrail refusal"
fi
