# BS2 0.2.1 — production trooper hardening

Patch release based on published 0.2.0 (`ce7bfcf`). The supported scope remains
governed pinned HTTP with durable Cairn memory, not a general shell sandbox.
No running fleet service or shared Cairn database is changed by this release.

## Fixed

- The production Claude CLI trooper now authors commands without independent
  tools, MCP servers or hooks. No permission-bypass flag; prompts go over stdin
  instead of process arguments. Model/backend/binary configuration is read at
  call time, with a portable `claude` default. Timeouts are bounded and the
  subprocess group is killed and reaped on expiry. Invalid configuration fails
  before a child starts; CLI errors cannot become executable model commands.
- `target-exec INCONCLUSIVE` now counts as an unsuccessful command and cannot
  close a coverage check. A timeout is not a proven negative.
- Target-controlled uid/getuid/session markers cannot prove shell/RCE execution.
  Both verdict and salvage paths reject those claims. The HTTP-only runtime has
  no independent host-execution proof mechanism; legacy text heuristics are not
  an acceptable substitute.
- Doctor messages now accurately describe mandatory approval and fail-closed
  missing-policy behavior. Historical architecture/test documents are labeled
  to prevent their older campaign recipes being mistaken for supported paths.

## Bounded validation

- **271 passed, 1 skipped** in the working tree, then **271 passed, 1 skipped**
  again from an extracted source archive in a fresh virtual environment. The
  skip is the optional external Battlestation engine, not a waived regression.
- **Opus driver and Opus trooper through the production launcher:** 8 model
  invocations, 60.618 seconds total measured model wall time, 7 loopback HTTP
  requests. The trooper independently authored five identity/resource controls;
  the receipt verifier correctly found owner-only enforcement. A fresh-process
  driver used Cairn to skip the unchanged check and reopen a changed generation.
  Repeating the negative caused zero target contact. A redirect was not followed,
  forged shell-marker content was returned only as HTTP data, and `curl -L`
  refused before contact. Marker non-promotion is additionally regression-tested.
- **Deterministic browser fixture:** 10 requests, one controlled confirmation and
  one controlled negative. Chromium rendered the panel, exact served context and
  a working source receipt link, with no page errors.
- **Synthetic restart benchmark:** Cairn retained 3/3 test facts versus 1/3 with
  capsules alone; 0 versus 1 redundant checks; zero unsupported conclusions in
  both arms. This is not a real-world model-performance benchmark.
- **Clean wheel:** installed with declared test extras in a new venv; isolated
  Python loaded the packaged runtime, trooper, Cairn and browser assets. CLI
  startup passed outside the checkout.

See the [sanitized machine summary](validation-0.2.1.json). Raw fixture prompts,
local environment diagnostics and assessment state are not public release assets.

## Limits and remaining rough edges

The dual-Opus harness adds a test-only route/principal allowlist and uses automatic
fixture-policy approvals, not human terminal clicks. The previous testing-only
canary substituted a safer model adapter; this release's canary exercised the
actual production launcher. The CLI was selected with `--model opus`; the six
trooper calls record configured model/launcher, not provider-reported model IDs.

Legacy banner handling still proposes an automatic `searchsploit` lookup. The
fixture rejected that unsupported command without target contact. Multi-protocol
recipes, old manager loops and broader finding types have not all been ported
to the current receipt contract. The panel's guide is explanatory but static,
not yet a fully contextual tutor. Consult the [0.2 runtime contract](RELEASE-0.2.md)
for containment limits and prerequisites. No real targets were tested.

## Reproduce

```bash
python3 -m pip install -e '.[test]'
python3 -m pytest -q tests
python3 -m playwright install chromium
python3 tools/release_check.py --browser --out /tmp/bs2-browser-check
# Requires a signed-in Claude CLI; at most eight model invocations:
python3 tools/dual_opus_check.py --out /tmp/bs2-dual-opus-check
```
