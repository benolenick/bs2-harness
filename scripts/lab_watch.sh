#!/usr/bin/env bash
# lab_watch.sh <juice-run.log> <crapi-run.log> — the improvement-loop supervisor.
#
# Emits ONE line per event worth acting on (step advance, retry, wedge, governed
# denial, crash, stall, terminal state) and exits when BOTH runs are terminal.
# Used as a Monitor event stream; the manager (Claude) acts on each event.
set -u
JUICE="${1:?}"; CRAPI="${2:?}"
declare -A last=( [juice]=-1 [crapi]=-1 )
declare -A retries=( [juice]=0 [crapi]=0 )
declare -A wedged=( [juice]=0 [crapi]=0 )
declare -A gov_seen=( [juice]=0 [crapi]=0 )
declare -A stale=( [juice]=0 [crapi]=0 )
declare -A done=( [juice]=0 [crapi]=0 )
emit(){ echo "$1"; }
mtime(){ stat -c %Y "$1" 2>/dev/null || echo 0; }

while true; do
  now=$(date +%s)
  for pair in "juice:$JUICE" "crapi:$CRAPI"; do
    name="${pair%%:*}"; log="${pair#*:}"
    [ "${done[$name]}" = 1 ] && continue
    if [ ! -f "$log" ]; then emit "$name: log missing"; sleep 30; continue 2; fi

    # terminal states (outcome-aware completion, or process gone)
    # P1-6: terminal classification reads the explicit terminal PROJECTION on the
    # final/report events (assessment_complete|closure_complete|stopped_incomplete) —
    # never free-text wording, which is how 'INCOMPLETE' once matched as 'COMPLETE'.
    if grep -qE "\[(final|report)\] .*projection=[a-z_]+" "$log"; then
      done[$name]=1
      emit "$name: TERMINAL — $(grep -oE "projection=[a-z_]+" "$log" | tail -1)"
      continue
    fi
    # AUTHORITATIVE fallback (pass-3 lesson 2026-08-25): a watch launched with a stale
    # script missed both projections and fell through to PROCESS GONE. report.json exists
    # ONLY at terminal time and carries terminal_projection — classify from the file, not
    # from any emit-line regex the running bash may or may not have loaded.
    rjson="${log%/*}/report.json"
    if [ -f "$rjson" ]; then
      done[$name]=1
      proj=$(grep -oE '"projection"[^,}]*' "$rjson" | head -1)
      emit "$name: TERMINAL (report.json) — $proj"
      continue
    fi
    pidfile="${log%/*}/RUN.pid"
    if [ -f "$pidfile" ]; then
      pid=$(cat "$pidfile")
      if ! kill -0 "$pid" 2>/dev/null; then
        # grace pass: the terminal writes (final/report emits + report.json) can land
        # a beat after the pid is gone — never classify from pid death alone
        sleep 30
        if grep -qE "\[(final|report)\] .*projection=[a-z_]+" "$log" \
           || [ -f "$rjson" ]; then
          done[$name]=1
          proj=$(grep -oE "projection=[a-z_]+" "$log" | tail -1)
          [ -z "$proj" ] && proj=$(grep -oE '"projection"[^,}]*' "$rjson" | head -1)
          emit "$name: TERMINAL (late) — $proj"
          continue
        fi
        done[$name]=1
        emit "$name: PROCESS GONE (pid $pid) — tail: $(tail -c 220 "$log" | tr '\n' ' ')"
        continue
      fi
    fi

    # step advance
    cur=$(grep -oE "step=[0-9]+" "$log" | tail -1 | cut -d= -f2); cur=${cur:-0}
    if [ "$cur" -gt "${last[$name]}" ]; then
      emit "$name: step $cur"
      last[$name]=$cur; retries[$name]=0; wedged[$name]=0; stale[$name]=0
    fi

    # retry storm / wedge
    r=$(grep -c "manager_retry.*step=$cur" "$log")
    if [ "$r" -gt "${retries[$name]}" ]; then retries[$name]=$r; emit "$name: retry $r @ step $cur"; fi
    if [ "$r" -ge 5 ] && [ "${wedged[$name]}" = 0 ]; then
      wedged[$name]=1; emit "$name: WEDGED step $cur ($r retries)"
    fi

    # governed denials / crashes
    g=$(grep -cE "GOVERNED (DENY|ERROR|CONFIG)|Traceback" "$log")
    if [ "$g" -gt "${gov_seen[$name]}" ]; then
      gov_seen[$name]=$g
      emit "$name: governed/crash #$g — $(grep -m1 -oE "GOVERNED (DENY|ERROR|CONFIG)[^|]{0,90}|Traceback[^|]{0,40}" "$log" | tail -1)"
    fi

    # stall: no new lines in 15 min while not terminal
    if [ $((now - $(mtime "$log"))) -gt 900 ]; then
      if [ "${stale[$name]}" = 0 ]; then stale[$name]=1; emit "$name: STALLED (log quiet >15min)"; fi
    fi
  done
  [ "${done[juice]}" = 1 ] && [ "${done[crapi]}" = 1 ] && { emit "BOTH TERMINAL — phase-1 loop over"; exit 0; }
  sleep 90
done
