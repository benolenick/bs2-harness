#!/usr/bin/env bash
# serve_governed — open the green BattleStation 2.0 page on a governed engagement.
# Renders THIS run's governed.sqlite3 (its terrain map, evidence, timeline), not the
# stale recipe-engine battle.  Usage: serve_governed.sh <RUN_DIR> [PORT]
set -uo pipefail
BS2=/mnt/sata/htb-bakeoff/bs2-governed-wt
RUN="${1:?usage: serve_governed.sh <RUN_DIR> [PORT]}"
PORT="${2:-8126}"
RUN="$(cd "$RUN" && pwd)"
DB="$RUN/governed.sqlite3"
[ -f "$DB" ] || { echo "no governed.sqlite3 in $RUN — open a seam first"; exit 2; }
BID="$(python3 -c "import json,sys;print(json.load(open('$RUN/seam.json'))['battle'])")"
# free the port if a prior view is running
fuser -k "${PORT}/tcp" 2>/dev/null || true
echo "serving green BattleStation 2.0 for battle $BID on http://127.0.0.1:${PORT}"
export PYTHONPATH="$BS2:${PYTHONPATH:-}"
exec python3 -m battlestation.cli --db "$DB" --ariadne-url off serve --host 127.0.0.1 --port "$PORT"
