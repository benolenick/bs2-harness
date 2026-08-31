#!/bin/bash
# Backstop watchdog for the ungoverned claude-cli trooper: Claude Code's Bash tool replaces
# `find` with its built-in `bfs` BELOW the PATH layer, so a PATH shim can't bound it. This
# reaper kills any bfs/find rooted at / (or /mnt) that survives >MAXAGE seconds — the finds
# that crawl the slow NTFS/FUSE mounts. Excludes non-pentest scans (.w3x). Self-exits when the
# sentinel file is removed or after TTL. General: no model cooperation required.
MAXAGE=${1:-25}
SENTINEL=${2:-/tmp/claude-1000/reaper.on}
TTL=${3:-5400}
touch "$SENTINEL"
START=$(date +%s)
while [ -f "$SENTINEL" ]; do
  now=$(date +%s)
  [ $((now-START)) -gt "$TTL" ] && break
  # kill offending long finds
  ps -eo pid,etimes,args | awk -v m="$MAXAGE" '
    /bfs .*(-iname|-name) / && $2>m && !/\.w3x/ && !/\.w3m/ {print $1}
    /find (\/|\/mnt)[^A-Za-z]/ && $2>m && !/find_reaper/ {print $1}
  ' | while read pid; do kill -KILL "$pid" 2>/dev/null && echo "$(date +%T) reaped stuck find pid=$pid"; done
  sleep 5
done
echo "reaper exit $(date +%T)"
