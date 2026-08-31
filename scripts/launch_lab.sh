#!/usr/bin/env bash
# launch_lab.sh juice|crapi [steps] — the BS2 all-systems lab test.
#
# Opens a governed seam for the local lab app and launches the canonical manager loop
# against it: GOVERNED fire, charter-scoped ports (never a -p- sweep of localhost),
# audited (GB_TARGET_AUDIT / GB_RAW_LOG), exec on THIS host (the target IS local).
set -euo pipefail
cd "$(dirname "$0")/.."

APP="${1:?usage: launch_lab.sh juice|crapi [steps]}"
STEPS="${2:-30}"
case "$APP" in
  juice) PORT=3006; CHARTER="charters/local_juice.json"; TARGET_URL="http://127.0.0.1:3006";;
  crapi) PORT=8888; CHARTER="charters/local_crapi.json"; TARGET_URL="http://127.0.0.1:8888";;
  *) echo "unknown app: $APP (juice|crapi)"; exit 1;;
esac

RUNBASE="/tmp/claude-1000/-home-om/lab-$APP-$(date +%s)"
mkdir -p "$RUNBASE"
SEAM_DIR="$RUNBASE/seam"

# BS2_HUMAN_APPROVAL (an ask-ben grant) authorizes the exploit caps; without it the
# seam opens recon-only and every fire attempt is governed-denied (fail-closed, by design).
# Read from ENV only — never put a grant on a command line.
python3 live/governed_seam.py open --target "$TARGET_URL" --run-dir "$SEAM_DIR" --ttl 43200
echo "seam open: $SEAM_DIR"

setsid nohup env \
  GB_CHARTER="$CHARTER" \
  GB_GOVERNED=1 BS2_SEAM_RUN="$SEAM_DIR" \
  BS2_HUMAN_APPROVAL="${BS2_HUMAN_APPROVAL:-}" \
  GB_TARGET_AUDIT="$RUNBASE/audit.jsonl" GB_RAW_LOG="$RUNBASE/raw.jsonl" \
  GB_TROOPER_TURNS=12 \
  TROOPER_EXEC_SSH= \
  python3 manager/run_htb.py 127.0.0.1 --model deepseek-v4-pro --steps "$STEPS" \
  > "$RUNBASE/run.log" 2>&1 &
echo $! > "$RUNBASE/RUN.pid"
echo "RUNBASE=$RUNBASE"
echo "launched: pid $(cat "$RUNBASE/RUN.pid") log $RUNBASE/run.log seam $SEAM_DIR"
