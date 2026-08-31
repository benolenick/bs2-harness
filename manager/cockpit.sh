#!/usr/bin/env bash
# cockpit — the MANAGER's single toolbox. The manager reasons + calls the shots; every
# engine below is just a tool it dispatches, all recorded in one governed ledger and read
# back through one content-blind status. This is the reorder's endpoint.
#
#   attack  <target> [min]   governed SIGHTED attacker (novel/web)   -> run_governed_pentest.sh
#   recipe  <target> [min]   autoturret / double-barrel (HTB decks)  -> run_double_barrel.sh
#   status  [--gov RUN]      content-blind status across both engines
#   goal|hold|directive ...  the 3 levers over the recipe engine     -> manager_bridge.py
#   ariadne <query>          advisory planner                        -> :8112
#   findings --gov RUN       governed findings + verified evidence
#   engage  <target> [dir]   THE ENTRYPOINT: open->MAP->PLAN->DISPATCH->GOVERN (LEVEL/ARM env)
#   map     <target> [dir]   app-surface map only (governed recon, 0 attack spend)
#   dispatch <sub> ...       expert-lane control: list|arm|disarm|level N|on/off <cls>|plan|run
#   level   <0|1|2|3>        set the dispatch level dial (L0 map .. L3 deep)
#   view    <run-dir> [port] open the GREEN BattleStation 2.0 on that governed run (:8126)
#   promote <run-dir>        bind findings to surface nodes (graph goes green)
#   arm | disarm             master spend-safety for the expert lane
#   reflex  --run-dir DIR     ground->reframe->fire autoturret cards on findings (0 LLM)
#   risk    readonly|safe|full impact ceiling (orthogonal to level); gates destructive ops
GB=/opt/bs2 ; LIVE=$GB/live ; MGR=$GB/manager
cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in
  attack)  exec bash "$LIVE/run_governed_pentest.sh" "$@" ;;
  recipe)  exec bash "$LIVE/run_double_barrel.sh" "$@" ;;
  status)
    if [ "${1:-}" = "--gov" ] && [ -n "${2:-}" ]; then
      echo "── governed attacker ──"; python3 "$LIVE/governed_seam.py" status --run-dir "$2"; echo
    fi
    echo "── recipe engine (autoturret) ──"
    ATRUN="${ATRUN:-$LIVE/../Desktop/HTB/enterprise-ab/bs2-memoria/atrun}" \
      python3 "$MGR/manager_bridge.py" status 2>/dev/null || echo "  (no recipe run / manager_bridge)" ;;
  goal|hold|directive|which|review)
    exec python3 "$MGR/manager_bridge.py" "$cmd" "$@" ;;
  ariadne)
    curl -s --max-time 6 "http://127.0.0.1:8112/plan?q=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(' '.join(sys.argv[1:])))" "$@")" \
      || echo "ariadne unreachable" ;;
  findings)
    [ "${1:-}" = "--gov" ] && exec python3 "$LIVE/governed_seam.py" status --run-dir "$2" ;;
  engage)  exec bash "$LIVE/run_engagement.sh" "$@" ;;
  map)     LEVEL=0 exec bash "$LIVE/run_engagement.sh" "$@" ;;
  dispatch) exec python3 "$LIVE/dispatch.py" "$@" ;;
  view)    exec bash "$LIVE/serve_governed.sh" "$@" ;;   # green BattleStation 2.0 on a governed run
  promote) exec python3 "$LIVE/surface_to_terrain.py" --promote --run-dir "$@" ;;
  reflex)  exec python3 "$LIVE/reflex_loop.py" "$@" ;;
  risk)    exec python3 "$LIVE/dispatch.py" risk "$@" ;;
  level)   exec python3 "$LIVE/dispatch.py" level "$@" ;;
  arm)     exec python3 "$LIVE/dispatch.py" arm ;;
  disarm)  exec python3 "$LIVE/dispatch.py" disarm ;;
  *) sed -n '2,12p' "$0" ;;
esac
