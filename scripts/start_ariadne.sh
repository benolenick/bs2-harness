#!/usr/bin/env bash
# Start the Ariadne attack-path planner that the BS2 manager consults.
# BS2 clients reach it at http://127.0.0.1:8112 (override: ARIADNE_PORT / GB_ARIADNE).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here/ariadne"
exec python3 ariadne/server.py
