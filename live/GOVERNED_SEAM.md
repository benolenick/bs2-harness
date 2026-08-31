# Governed seam — the reorder (sighted attacker THROUGH BS2 governance)

The fix for "BS2 can't be pointed at anything": stop making the recipe engine the main
line. Put a SIGHTED reasoning attacker (the claude-pentest agents) at the FRONT, and run
its on-target commands THROUGH BS2's GovernedExecutor so governance becomes a LEDGER that
wraps a working attacker instead of a recipe-toy standing in for one.

```
attacker agents (see raw, reason, act)         <- the engine (claude-pentest plugin)
        │  gexec "<cmd>"
        ▼
GovernedExecutor.execute()  default-deny gate -> runs cmd -> records
    capability.issued / tool.dispatched / tool.completed   (or tool.denied)
        │
BS2 event log + proof-gates + hash-chained audit           <- governance (the wrapper)
```

Content-blindness is now a property of the RECORD, not the reasoner:
- the ATTACKER sees raw stdout (it is the operator/hands+brain);
- the LEDGER stores only sha256 + metadata, raw stays dirty-side by content hash;
- the MANAGER view (`events`) reads the scrubbed event stream only.

## Use it

1. Open a governed battle for the target (mints capabilities from an activated charter):
   python3 /opt/bs2/live/governed_seam.py open --target http://127.0.0.1:3060 --run-dir <RUN>

2. The attacker runs every on-target command through the seam. Either:
   - directly:  python3 governed_seam.py exec --run-dir <RUN> --class web.exploit -- <cmd...>
   - or the shim:  BS2_SEAM_RUN=<RUN> GEXEC_CLASS=web.recon  gexec <cmd...>

3. Manager (content-blind) reads the ledger:
   python3 governed_seam.py events --run-dir <RUN>

## Wiring the claude-pentest agents (the runner)

Point the plugin's executor/inventory agents at the target and tell them, in the brief,
to run on-target commands via `gexec` (export BS2_SEAM_RUN and set GEXEC_CLASS per phase:
web.recon for inventory agents, web.exploit for testers). Their reasoning is unchanged;
only the exec path is governed. The recipe engine (autoturret) is untouched and parallel.

## Proven (2026-08-23, juice-shop wb v20.2.0)
recon + SQLi login bypass (`' OR 1=1--` -> real JWT) ran THROUGH the seam; 12 governed
events recorded; manager view scrubbed (no token/creds/raw); gate denied `rm` and
over-ceiling risk. Files: governed_seam.py, gexec, this doc.
