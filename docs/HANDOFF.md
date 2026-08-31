# BS2 ↔ MIT A/B — package handoff

This package is the BS2 pentest harness (manager-in-the-loop, fully governed) plus
the machine that runs a FAIR, blind, reset-state A/B against the MIT claude-pentest
harness on OWASP crAPI.

## The 5-minute path

```bash
# 1. install everything (one doc, complete audit)
cat docs/DEPENDENCIES.md

# 2. stand up the A/B target (crAPI + MailHog) and the canary (Juice Shop)
cat docs/STANDUP.md
crapi status && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8888/   # 200

# 3. prove the box is sane: the suite IS the spec
python3 -m pytest tests/ -q                       # all pass, 1 known skip

# 4. sanity ceiling: the answer key run on a FRESH board
python3 scorer/crapi_score.py                     # 8 SOLVED / 8 auto-gradeable

# 5. run the BS2 side (reset-state, governed)
python3 scripts/ab_run.py --side bs2 --steps 30

# 6. de-seed the MIT harness, then run its side
cat docs/MIT_DE-SEEDING.md
python3 scripts/ab_run.py --side mit --steps 30 --cmd 'your-mit-launch.sh'

# 7. score both against the SAME key
python3 scripts/ab_score.py --a ab_artifacts/bs2-<ts> --b ab_artifacts/mit-<ts>

# 8. write the final report (methods, fairness checklist, both score tables,
#    verdict, caveats) — TESTING.md §5 has the skeleton and grading rules
```

## Doc index (read in this order)

| Doc | For |
|---|---|
| `docs/DEPENDENCIES.md` | every tool/package/service to install, verified list |
| `docs/STANDUP.md` | exact recipes: crAPI stack, isolated dockerd, MailHog, Juice Shop, reset contract |
| `docs/TESTING.md` | the suite (the spec), the lab canary, the A/B protocol, the green gate |
| `docs/ARCHITECTURE.md` | the canonical loop, file map, governance spine, fix-it recipe, known traps |
| `docs/MIT_DE-SEEDING.md` | how to strip the MIT harness's answer-key seeding and PROVE it |
| `scorer/crapi_score.py` | the reference scorer = the answer key (keep OUT of both harnesses) |
| `docs/challenges.md` | crAPI's 18 documented challenges — the transcript-grading list |

## The fairness contract (non-negotiable)

1. `crapi reset` between EVERY side — never two harnesses on one board.
2. Scorer sanity (8/8) after every reset, BEFORE the harness touches the board.
3. Identical step budget and model TIER for both brains.
4. MIT side de-seeded first (see MIT_DE-SEEDING.md §2 for the proof procedure).
5. The answer key lives in the SCORER, which neither harness sees; the machine
   grades the 8 auto challenges by route overlap, a human grades the 10
   transcript items from the same challenge list.

## If something breaks

`docs/ARCHITECTURE.md` → "Fix-it recipe": reproduce in a test first, root-cause at
the mechanism, full suite green before any commit, fix rides the next pass, never
mutate a running engagement. The suite is the spec; the canary is the proof.
