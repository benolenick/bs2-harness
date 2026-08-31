# BS2 architecture + how to implement and fix it

Written for an agent that must understand, extend, and repair this system without
the original builder. Read this before touching code; the tests are the contract.

## The canonical loop (memorize this shape)

```
Charter (human-approved scope) ──gate──▶ Hands (routine recon, charter-scoped sweeps)
      │                                        │  folds discovery
      ▼                                        ▼
   Cartographer (durable map: nodes + lifecycle + frontier)
      │                                        │  frontier/coverage/report
      ▼                                        ▼
   Ariadne (routes/recall consultant) ──▶ Manager (Opus-class, CONTENT-BLIND,
      │                                     authors ONE objective/command per step
      ▼                                     from the live picture)
   Trooper (cheap model: pure TRIGGER — fires the authored command,
      │        returns a SANITIZED marker only)
      ▼
   BS2 door (target_exec §10.1 — the ONLY target-contact path; governed seam:
      │        capability TTL/scope/risk ceilings, cmd_sha audit, tamper detection)
      ▼
   Verifier (skeptic, disprove-first, fail-closed confirmation)
      ▼
   Fold (cartographer ingests receipts; new surfaces become frontier → next step
         redispatching happens AUTOMATICALLY because the picture is rebuilt each step)
```

Rules that keep this loop honest:
- **The manager never sees raw output** — only facts, scrubbed markers, map state.
- **Catalog is a library, never a decider** — recipes index lanes; the manager picks.
- **Terminal states are exactly three**: `assessment_complete` / `closure_complete` /
  `stopped_incomplete`, derived deterministically from the coverage report
  (`live/cartographer/coverage.py::terminal_projection`). Never free-text.
- **Never mutate a live run.** Fixes ride the NEXT pass.

## File map

| Path | What it is |
|---|---|
| `manager/run_htb.py` | THE canonical engine: charter gate, loop, wedge breakers, terminal projection |
| `manager/run_deep_deepseek.py` | crAPI-specific manager-in-the-loop driver + BOLA slice consumer |
| `manager/manager_bridge.py` | Opus-manager tool surface (content-blind status + levers) over autoturret |
| `live/cartographer/` | durable map: `core.py` (fold/frontier/rebuild-from-events), `coverage.py` (completion truth), `report.py` |
| `live/hands.py` | routine recon owner: recon_sweep (charter-port aware), verify_vhosts |
| `live/trooper.py` | cheap trigger: scope guard (host + charter ports + redzones), fire-time env reads |
| `live/target_exec.py` | §10.1 door — the only place commands contact the target |
| `live/governed_seam.py` | seam: open/exec/events/attested/verify/finding/stop (STOP marker invalidates caps) |
| `live/governed_runner.py` | request_spec → governed curl → normalized response record |
| `live/bola_slice.py` | P1-2 slice CORE: id_sources → principals → bound anon ownership-diff BOLA matrix |
| `live/differential.py` | HTTP replay engine: matrix + structured deltas + ownership verdict |
| `live/lab.py` | BS2 HTTP Laboratory: observe → run → confirm (fail-closed skeptic gate) |
| `live/skeptic.py` | disprove-first verifier checklist + verdicts |
| `live/observation.py` | ObservationRecord — the ONE typed record; validate() is the structural contract |
| `live/experiment_ledger.py` | no-repeat ledger: fingerprint → should_retest; `open(run_dir)` = shared-lane entry |
| `live/ab_runner.py`, `live/ab_score.py` | the blind reset-state A/B machine |
| `scripts/` | CLIs: launch_lab.sh, lab_watch.sh, lab_slice.py, ab_run.py, ab_score.py |
| `charters/` | human-approved scope files (local_juice.json / local_crapi.json) |
| `lab_plans/crapi.json` | slice plan (endpoints + id_sources + principals-as-REFS) |
| `tests/` | THE CONTRACT — see TESTING.md |

## The governance spine (what MIT's harness does not have)

1. **Governed seam** — capabilities with TTL, scope hosts (CIDR), budgets, max_risk.
   Open = one approval per episode. `stop` writes a STOP marker; exec then refuses.
   Recon-only seam = caps `web.recon`/`net.recon`, max_risk low.
2. **BS2 evaluate** — every trooper/recipe command routes its capability class through
   `target_exec.classify_action`; AUTOTURRET is a manager verb, never an auto.
3. **Separation of duties** — the engine executes and hashes dirty artifacts
   (`dirty/{wid}.raw`); the verifier independently re-checks; tamper detection on
   the CAS ledger.
4. **Fail-closed everywhere** — unconfirmed records never enter the map as findings;
   incomplete skeptic checklists hold; denied commands burn steps and the
   denial-cascade wedge folds honestly after 4 consecutive denials.
5. **Charter gates** — run start refuses a non-chartered target; the trooper scope
   guard reads `GB_ALLOW_LOOPBACK` + `GB_CHARTER_PORTS` at FIRE time (env set at
   run start, read per command — an import-time read is a trap that silently walls
   every command; see the lab pass 2–3 history).

## How each piece is proven (and how to prove a change)

- Pure logic → `tests/` (213+ tests; the suite IS the spec).
- Mechanism that touches the target → lab canary pass: `scripts/launch_lab.sh <juice|crapi> <steps>`
  then `scripts/lab_watch.sh <log1> <log2>`. A pass is good when commands actually
  FIRE through the seam (real `ran` receipts), coverage moves, and the terminal
  projection is emitted and classified.
- The whole loop end-to-end → the 14-injection contract test `tests/test_e2e_contract.py`
  (drives a REAL seam via subprocess) and the A/B machine (`scripts/ab_run.py`).

## Known open items (state at handoff)

- **P0-2**: an ungoverned target-contact fallback still exists in one path —
  removal needs the operator's sign-off. Do NOT remove it yourself; ask.
- **Browser/specialist operations** (Playwright lanes, auth-state coordination
  between specialists): under active development by a separate specialist-upgrade
  effort — integrate against the canonical-loop interfaces above, do not re-implement.
- **Trooper path honors charter ports** as of 2026-08-25 (GB_CHARTER_PORTS); hands
  always did. Keep both.

## Fix-it recipe (when something breaks)

1. Read the failing signal from the RUN LOG — the emit lines are structured
   `[kind] key=value`; `[final]`/`[report]` carry `projection=`/`projection_reason=`.
2. Reproduce in a test FIRST (`tests/` + `python3 -m pytest tests/ -q`). Green gate:
   the full suite must pass before any commit.
3. Root-cause at the mechanism level, not the symptom. The classic traps already
   found: import-time env reads (fire-time only), `INCOMPLETE` matching `COMPLETE`
   (projection events only), ledgers built but never saved (dedup silently dead),
   stub bindings (`differential._binding_for` returns {} — callers must bind),
   numeric DB ids vs uuid fields in plans, secrets in argv (never — 600 files/env
   only), raw-log capture on for authenticated sessions (off), salvage paths
   blind to the data shape (pass 6: the transcript held the full crAPI page but
   salvage only knew service-banner patterns, so six steps folded zero facts —
   every deterministic extraction layer must cover the web-transcript shape, not
   just nmap/ssh output), and engine-emitted reflex chunks masquerading as
   target output in diagnostics (the auto-searchsploit "No Results" was read as
   the target's "no results" wall).
4. Fix rides the NEXT pass — never mutate a running engagement.
5. After the fix: full suite green → commit → one small canary pass → fold the
   result honestly. The verify step is the one that matters.
