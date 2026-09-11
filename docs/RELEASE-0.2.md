# BS2 0.2.0 — durable memory and a fail-closed HTTP runtime

This is a **breaking safety release**, built on published master `2c1aefb`, not
the older unrelated unified Battlestation checkout. It does not install or modify
the fleet's running BS2 services or shared Cairn database.

## Six delivered changes

1. Canonical exact-request approval binds command, parsed execution plan, pinned
   DNS answers, host/port, policy digest, timeout, assessment, conditions and a
   single-use nonce/expiry. Policy and expiry are checked again before dispatch.
   No proxy, redirect, second DNS lookup or raw-shell fallback exists in the
   supported runtime. Legacy execution dispatches refuse.
2. Existing Cairn store/assembler vendored with a BS2 adapter. Receipts fold
   automatically; supported manager turns receive a persisted, source-qualified
   context slice. Observation and hypothesis status are never silently promoted.
3. Controlled private-resource verification needs owner, distinct authenticated
   other, and anonymous responses plus independent identity controls. Timeouts,
   target text markers, model confidence and missing controls cannot confirm.
4. Negative results are scoped to request, principals/credentials, session epoch,
   target generation and privacy contract. Identical checks suppress; changes or
   evidence older than 24 hours reopen. Missing conditions mean unknown, not drift.
5. Read-only operator panel: Known, Suspected, Already tried, Changed, Next check,
   tutor explanation, exact last Cairn slice and source receipt links. Loopback,
   origin guard, CSP, safe text rendering, and no write endpoints.
6. Reproducible deterministic capsule-vs-Cairn restart benchmark and bounded
   Opus-driven fixture canary. This is a state-retention test, not a real-world
   model-performance or exploitation benchmark.

## Important limits

Application-level **pinned HTTP containment is not an OS sandbox**. This machine
refused namespace isolation. No general sandbox for arbitrary network tools is
bundled. nmap, nuclei, SSH, shell pipelines, redirects, proxy routing, Host header
overrides, cookie-file references and uploads are deliberately rejected. Existing
recipe/lane code remains in the source tree for future porting, not as an escape
path. Run the documented bounded HTTP workflow; do not launch historical campaign
scripts expecting full multi-protocol compatibility.

The test approver is an explicitly bounded fixture policy, not a fake human click.
Interactive terminal y/n has not been manually exercised by Ben. Model service
credentials and optional attack tools are not installed by this release. The
optional external Battlestation engine suite is skipped when that package is not
explicitly installed; it no longer discovers a hardcoded workstation checkout.

## Reproduce

Validation: **254 tests passed**, one optional external-engine module skipped.
Opus drove two controlled checks (10 fixture HTTP requests) and judged the result.
Rendered panel, exact context and source links passed in Chromium. A clean venv
installed the wheel and loaded the runtime, Cairn and UI assets independently.
The complete suite also passed from an extracted source archive in a fresh venv;
this caught and fixed Flask missing from the declared test extras.
The corrected synthetic restart scorer retained **3/3** facts with Cairn versus
**1/3** from capsules alone, with **0 vs 1** redundant checks. Both arms made zero
unsupported conclusions. See [machine summary](validation-0.2.json).

```bash
python3 -m pip install -e '.[test]'
python3 -m pytest -q tests
python3 -m playwright install chromium
python3 tools/release_check.py --opus --browser --out /tmp/bs2-validation
```

The canary permits two Opus-selected controlled checks, five local requests each,
then one Opus judgment. There are no specialists, real targets or indefinite loops.
Omit `--opus` for a deterministic final smoke with no model calls.
