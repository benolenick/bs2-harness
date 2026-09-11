# Testing BS2 — the gate, the canary, the A/B

Historical test plan. Current release commands and limits are in the
[README](../README.md#test) and [0.2.1 release notes](RELEASE-0.2.1.md).
The old campaign recipes and external capability seam below are not supported
execution alternatives. Current SIGIL/AGENTS instructions take precedence.

## 1. The unit/integration suite (run before EVERY change and EVERY commit)

```bash
cd gunbelt
python3 -m pytest tests/ -q            # expect: all pass, 1 known skip
python3 -m pytest tests/test_X.py -q   # one file
python3 -m pytest tests/test_X.py::test_name -q   # one test
```

The suite is the SPEC. What the key files pin:

| File | Pins |
|---|---|
| `test_canonical_loop.py` | charter gate, hands recon ownership, catalog-is-a-library, trooper scope guard (loopback carve-out FIRE-time + charter ports), manager redispatch on new surfaces, run identity per charter ports |
| `test_e2e_contract.py` | the ENTIRE loop against a real governed seam (subprocess), + 14 fail-closed injections. One explicit skip: target_generation enforcement (enumerated gap) |
| `test_terminal_projection.py` | the three terminal states + blockers (P1-6) |
| `test_tools_registry.py` | every tool capability probed or recorded, never assumed (P1-3) |
| `test_manager_bridge.py` | lever audit chain: intent → materialize → completion, hash-chained (P1-4) |
| `test_bola_slice.py` | the BOLA slice matrix: same-schema ownership-diff catch, 403 negative, fail-closed confirm, ledger persistence/dedup, scrubbed markers |
| `test_ab_runner.py` | A/B machine: all four terminal paths, route matching vs the answer key, honesty scoring, reset-failure abort |

Writing a test: fake the runner (a function returning normalized records or command
output); never touch the network. For env-sensitive code use `monkeypatch.setenv` —
and remember module-level env sets from `run_deep_deepseek` imports leak across
tests; own the env var in the test.

## 2. The lab canary (mechanism proof against a real target)

```bash
bash scripts/launch_lab.sh juice 30     # or crapi; opens a governed seam + launches
bash scripts/launch_lab.sh crapi 10     # SMALL steps cap = proof, not grind
```

Then watch (event stream, exits when terminal):

```bash
bash scripts/lab_watch.sh /tmp/claude-1000/-home-om/lab-juice-<ts>/run.log \
                         /tmp/claude-1000/-home-om/lab-crapi-<ts>/run.log
```

What "good" looks like:
- `ran` events with REAL observed facts (statuses, schemas) — not `scope-guard` blocks
- coverage pct moving up (or the map growing with an honest explanation — a foothold
  OPENS the interior frontier and pct drops until the new surface is enumerated)
- terminal: `TERMINAL — projection=stopped_incomplete|assessment_complete|closure_complete`
  — classified from the PROJECTION (log line or report.json), never from wording
- a forced stop is ALWAYS `stopped_incomplete` — honest, not a success variant

Stopping a run early (proof captured, don't grind):
`python3 live/governed_seam.py stop --run-dir <seam-dir>` — the engine folds via the
denial cascade and still writes its terminal projection. Then kill the pid if needed.

## 3. The A/B (fair, blind, reset-state)

One side at a time, from the HANDOFF protocol:

```bash
python3 scripts/ab_run.py --side bs2 --steps 30          # BS2 side (governed)
python3 scripts/ab_run.py --side mit --steps 30 --cmd 'your-mit-harness-launch.sh'
```

Each `ab_run` does: `crapi reset` → wait healthy → launch → wait terminal → collect
normalized artifacts (report/map/meta + the reference scorer run on the SAME board)
→ `ab_artifacts/<side>-<ts>/`.

Then score (the answer key is the SAME for both):

```bash
python3 scripts/ab_score.py --a ab_artifacts/bs2-<ts> --b ab_artifacts/mit-<ts>
python3 scripts/ab_score.py --a <dir> --json        # machine JSON
```

Machine-graded: the 8 auto-gradeable challenges (route overlap vs the key).
Human-graded: the printed checklist (10 items, both harnesses' transcripts vs
`docs/challenges.md`).

Fairness rules:
- `crapi reset` between EVERY side (never two harnesses on one board)
- scorer sanity (`8 SOLVED / 8 auto-gradeable`) after each reset, BEFORE the run
- identical step budget and model tier for both sides
- the MIT harness must be DE-SEEDED first — see MIT_DE-SEEDING.md

## 5. The final A/B report

After BOTH sides have run, assemble the report:

1. **Collect the artifacts.** Each `ab_artifacts/<side>-<ts>/` holds the per-run
   `report.json` (terminal projection, findings, honesty statement), `map.json`,
   `run.meta.json`, and `scoreboard.json` (the reference scorer run on the SAME
   board the harness ran on — the machine answer key).
2. **Run the score.** `python3 scripts/ab_score.py --a <bs2-dir> --b <mit-dir>` —
   prints the auto score per side (route-matched challenges, discovery coverage,
   foothold, efficiency, honesty) and a verdict (winner, or tie within 5 points).
3. **Grade the transcripts.** Walk the 10 transcript items against
   `docs/challenges.md` (the same list for both sides) and mark which side
   satisfied each. Do this WITHOUT consulting the scorer output first — the human
   grade must not be seeded by the machine grade.
4. **Write the report** with this skeleton:
   - *Methods*: board version, reset protocol, step budget, model tier per side,
     reference to the de-seeding proof (MIT_DE-SEEDING.md §2)
   - *Fairness checklist*: the 5 contract items, each confirmed by the artifact
     or command that proves it held
   - *Scores*: the machine table (per-challenge route overlap) + the human
     transcript table (challenge → BS2 → MIT → note)
   - *Verdict*: winner by score; within 5 points = call it a tie and say why
   - *Caveats*: every deviation (model-tier mismatch, an aborted run, a scorer
     anomaly) — honesty in the report is part of the result, not a footnote

The per-run `report.json`/`report.md` the harness writes is its own honest
terminal statement; the A/B report is the separate assembly over BOTH sides.

## 4. The green gate (never skip)

1. `python3 -m pytest tests/ -q` → all pass
2. commit (suite green is the ONLY gate; a red suite never commits)
3. if the change touches target-facing mechanics: one small canary pass (steps ≤ 10)
4. fold the result into the day-log + project log honestly (projection, not spin)
