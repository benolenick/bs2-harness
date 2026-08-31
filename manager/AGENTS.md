# Lenz boundary (mandatory)

Never read, list, search, grep, tail, parse, copy, summarize, or otherwise inspect raw BS2
run directories matching `/tmp/claude-1000/-home-om/htb-*`. Never inspect their telemetry,
state, cartography, reports, timelines, reasoning logs, filenames, process command lines, or
target identifiers through another route.

For every BS2 run assessment, use only:

```sh
/opt/bs2/bin/lenz latest
/opt/bs2/bin/lenz verify
```

Lenz output is the complete observer contract. If Lenz reports `observer.state=blocked`,
report that the observer is blocked; do not bypass it. Humans and the non-agent Lenz service
retain the raw artifacts for audit.

Do not execute `run_htb.py`, `lenz_projector.py`, a live trooper, or target-facing tests
from Codex. The root-owned system service is the only raw-side projector. The public CLI
verifies an exact v2 schema, Ed25519 signature, and current service heartbeat.
