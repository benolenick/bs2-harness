# Stripping the cheats out of the MIT harness

The MIT claude-pentest harness must run FAIR against BS2. Our own investigation
found its marquee score is inflated by seeding:

- its "91/91 reachable" benchmark run carried **answer keys**: the harness (or its
  test scaffolding) knew the targets/answers in advance;
- one evaluation "arm" was a **fake naked model** (not the real specialist model);
- per-target tuning means Juice Shop results in particular reflect memorized
  challenge knowledge, not found-it-live.

This document is the de-seeding procedure: find the leaks, cut them, prove the cut.

## 1. The four leak shapes to hunt

### A. Answer keys in the harness code or configs

Anything in the harness repo that names a vuln, endpoint, flag, or credential
BEFORE a run. Concrete grep sweeps (run in the MIT harness repo):

```bash
# HTB flag format (HTB{...}) anywhere outside tests/answers
grep -rn "HTB{" . --include="*.py" --include="*.js" --include="*.json" \
  --include="*.md" --include="*.txt" --include="*.yaml" --include="*.yml" | grep -v "test"
# crAPI challenge names / endpoints seeded as hints
grep -rniE "vehicleid|contact_mechanic|validate-coupon|posts/recent|kid.*traversal|AA==" . \
  --include="*.py" --include="*.json" --include="*.md" | grep -viE "test|readme|docs/"
# juice shop challenge names (the overfit set)
grep -rniE "acid burn|product tampering|zero stars|basket access" . --include="*.py" --include="*.json"
# hardcoded credentials
grep -rnE "password\s*=\s*['\"][^'\"]+|token\s*=\s*['\"][A-Za-z0-9_-]{20,}" . --include="*.py"
```

Anything that hits is a candidate seed. Judge each: a REAL general-purpose payload
list is fine (SecLists lives in the tool, not the brain); a per-target answer is a
cheat. Cut the per-target ones.

### B. Prompts that name the answer

Sweep the prompts the harness SENDS to its models:

```bash
grep -rnE "you (should|will|can) find|hint|known vulnerability|the answer is|flag is|exploit .* with" . \
  --include="*.py" --include="*.txt" --include="*.md" | grep -viE "test|docs"
```

A fair specialist prompt describes the OBSERVED state (ports, banners, responses)
and the task — never the vuln class of the box, never the next step. If a prompt
says "this is GitLab 13.10, CVE-2021-22205" before the model observed anything,
the harness supplied the exploit chain; that's a leak.

### C. Evaluation arms that aren't the real model

```bash
grep -rnE "mock|fake|naked|stub|dummy|simulate|oracle" . --include="*.py" \
  | grep -viE "test|fixture"
```

Find every code path where a "model" can be swapped for a scripted answerer.
The reported benchmark numbers must come from the REAL model path only. Any arm
that isn't, delete or (if you must keep it) exclude from every reported number.

### D. Per-target tuning / overfit configuration

```bash
find . -iname "*juice*" -o -iname "*crapi*" -o -iname "*target*" | head -40
grep -rnE "target_specific|per_target|override.*target|if .*target.*==" . --include="*.py" | grep -v test
```

Look for branches that change strategy/hints per named target. A harness may have
target-agnostic engine knobs (budgets, timeouts); it must not have target-named
intelligence (e.g. a file of known Juice Shop solutions loaded at runtime).

## 2. The verification procedure (prove the cut)

After cutting, PROVE the harness is clean before the A/B:

1. **Static**: re-run all four sweeps above → zero per-target hits (general payload
   lists and test fixtures excepted).
2. **Blind virgin run**: point the harness at a target it has NEVER been tuned on —
   crAPI on a fresh board. Watch the first few turns' prompts/logs: the model must
   be given only observed state. Any mention of a crAPI challenge name, route, or
   vuln class in the harness-supplied text = still leaking.
3. **Sanity comparison**: if the harness solves crAPI's documented challenges at a
   rate wildly above a plain capable model given the same observed state, suspect
   remaining seeds; investigate before trusting the number.

## 3. What the A/B then compares

- Same fresh board (`crapi reset` between sides), same step budget, same model
  TIER for the brain (not necessarily the same vendor — tier, not brand).
- The 8 auto-gradeable challenges graded by route overlap against the reference
  scorer (`scorer/crapi_score.py` — it IS the answer key, kept OUT of both
  harnesses), the 10 transcript items by a human against
  `docs/challenges.md` (same list for both).
- Score: `scripts/ab_score.py --a <bs2-artifacts> --b <mit-artifacts>`.

If MIT's de-seeded run still wins raw speed on its tuned targets — expected, and
fine; the A/B target is crAPI, which neither side gets to memorize.
