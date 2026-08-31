# BS2 pentest system — proper start

## 0. Preflight (always first)
```
bash /opt/bs2/manager/bs2_preflight.sh   # 7 checks, GPU0-safe (never starts vLLM)
```
All 7 must be UP before an engagement. Fix any DOWN with the command it prints.

## 1. Boot order (only what preflight says is DOWN)
1. **ariadne :8112** — the planner brain. `cd /home/operator/ariadne && systemctl --user start ariadne`
2. **vLLM :8000** — GPU0, SHARED. **Never** auto-start; if down, ask Ben. Ariadne extract/distill needs it.
3. **bs2 ui :8125** — `cd .../battlestation && python3 server.py --ariadne-url http://127.0.0.1:8112`
4. **sigil topology** — `python3 /opt/bs2/.sigil/build_topology.py` (idempotent)

## 2. Per-engagement (one target)
```
RUN=<run-dir>
cd /opt/bs2/live
python3 governed_seam.py open --target <url|host> --run-dir $RUN   # governance receipt + hash-chained ledger
python3 web_surface_mapper.py --run-dir $RUN                       # anon surface -> worklist.json
# (API/authed target: seed worklist.json from authed recon — the mapper can't auth yet)
```

## 3. Advisory (manager decides)
```
cd /opt/bs2/manager
AUTOTURRET_RUN=$RUN python3 manager_bridge.py advise --posture <broadside|measured|surgical> --json
```
-> {goals, recon_next, troopers[], posture}. Troopers gated by posture. join_src=worklist means real surface.

## 4. Dispatch specialists (content-blind)
- Manager NEVER runs on-target commands or reads raw exploit output (guardrail).
- One Sonnet trooper per selected class, each given the brief
  `/opt/bs2/mailbox/troopers/crapi_trooper_brief.md` (generalize per target).
- Trooper routes ALL target-touching cmds through `governed_seam.py exec` (hash-chained),
  records confirmed vulns via `governed_seam.py finding --work-id`, returns SCRUBBED JSON only.

## 5. Telemetry + guardrail audit (know if a trooper failed)
```
bash /opt/bs2/manager/trooper_audit.sh $RUN <baseline_event_count>
python3 governed_seam.py events --run-dir $RUN     # scrubbed manager view
python3 governed_seam.py status --run-dir $RUN
```
A trooper that produced 0 governed rows / returned non-JSON = guardrail refusal or crash -> flag + ping Ben.
