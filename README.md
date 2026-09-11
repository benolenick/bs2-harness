# BS2 — governed assessments with Cairn memory

BS2 0.2 connects exact operator approvals, controlled HTTP verification, durable
Cairn memory, and a read-only operator panel. Models propose work; execution and
evidence decide what actually happened.

**Breaking safety change:** the supported portable backend is pinned HTTP, not a
general shell or multi-protocol scanner. Unsupported shell commands, SSH/seam
dispatch, proxies, redirects and cookie files refuse rather than run uncontained.
See the [0.2 runtime contract](docs/RELEASE-0.2.md) before migrating an older
campaign. Latest patch: [0.2.1 release notes](docs/RELEASE-0.2.1.md).

## What's new

- 0.2.1 hardens the production Claude trooper: independent tools and hooks are
  disabled, prompts use stdin, inconclusive requests cannot complete checks, and
  text-only shell claims are rejected in both verdict and salvage paths.
- Exact, expiring approvals bind the command, HTTP execution plan, destination,
  policy and assessment context. Scope and policy are rechecked before dispatch.
- Your existing **Cairn** implementation now folds BS2 receipts automatically and
  serves source-qualified memory before supported manager turns. It is distinct
  from Cartographer's map and Memoria's advisory corpus. [Memory contract](docs/CAIRN.md).
- Private-resource verification compares owner / other / anonymous requests plus
  two authenticated identity controls. Model confidence is never proof.
- Proven negative checks suppress only under matching conditions. Changed
  sessions, principals, target generations or privacy contracts reopen them.
- Browser panel: Known, Suspected, Already tried, Changed, Next check, tutor
  explanation, exact served Cairn slice and source links.

## Install and configure

Python 3.10+:

```bash
python3 -m pip install -e '.[test]'
python3 scripts/bs2-doctor --require-hitl --json
```

The initial doctor should fail until scope, the broker and durable storage are
configured. Apply its actionable fixes; never bypass a failure.

```bash
mkdir -p ~/.config/bs2
chmod 700 ~/.config/bs2
cp policy.example.json ~/.config/bs2/policy.json
chmod 600 ~/.config/bs2/policy.json
# Edit allowed_hosts and allowed_ports to your explicitly authorized target.
# Or use: python3 scripts/bs2-roe
export BS2_GOVERNANCE_POLICY="$HOME/.config/bs2/policy.json"
export BS2_GOVERNANCE_BROKER_URL=http://127.0.0.1:8129
export BS2_GOVERNANCE_BROKER_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export BS2_RUN_DIR="$HOME/.local/state/bs2/my-assessment"
export BS2_TARGET=198.51.100.10
```

In terminals sharing that environment:

```bash
python3 live/broker/bs2_cli_broker.py
python3 live/broker/bs2_gate.py
```

Approval is mandatory regardless of the old `BS2_REQUIRE_HITL` toggle. An optional
policy servicer requires an explicit operator-reviewed exact-command hash list;
it no longer approves arbitrary commands by IP heuristics.

## A bounded controlled check

Only run against a service you are authorized to test. Provision two distinct test
accounts. Set `BS2_OWNER_TOKEN` and `BS2_OTHER_TOKEN` privately (do not commit them).
The identity endpoint must return `{"principal_id":"alice"}` / `"bob"`; the private
resource must expose `id` and `owner_id`. Other application schemas need an explicit
verifier adapter, not a guessed conclusion.

```bash
python3 scripts/bs2-doctor --require-hitl
bs2 --run-dir "$BS2_RUN_DIR" check-read \
  --base http://198.51.100.10 --route /private/1 --identity-route /whoami \
  --owner alice --other bob --resource-id 1 \
  --private-contract "This resource is private to its owner" \
  --generation deployment-1 --session-epoch accounts-1

bs2 --run-dir "$BS2_RUN_DIR" context
bs2-ui --run-dir "$BS2_RUN_DIR"
```

Open `http://127.0.0.1:8130`. Approvals stay in the terminal; the panel is read-only.
Keep the same run directory to resume. Update generation/session identifiers when
the deployment or account state changes. An unchanged proven-negative check is
suppressed without target contact. Unknown outcomes remain inconclusive.

## Test

```bash
python3 -m pytest -q tests
python3 -m playwright install chromium
python3 tools/release_check.py --opus --browser --out /tmp/bs2-validation
```

The canary lets Opus select exactly two controlled checks against a disposable
loopback fixture: ten HTTP requests total, then one judgment. No specialists,
real targets or indefinite campaign. Omit `--opus` for a deterministic smoke.

To additionally test Opus as both driver and trooper, through the production
tool-disabled Claude launcher (requires a signed-in `claude` CLI):

```bash
python3 tools/dual_opus_check.py --out /tmp/bs2-dual-opus
```

This separate test caps at eight model calls and seven loopback HTTP requests.
It checks controlled verification, Cairn across a fresh process, repeat
suppression and redirect refusal. A test-only route/principal allowlist further
restricts the fixture; it is not a general campaign or an OS sandbox test.
Outside the fixture, select this launcher with `TROOPER_BASE=claude-cli` and
`TROOPER_MODEL=opus`; approval, policy and durable-storage requirements still apply.

The source tree retains Ariadne, recipe catalogs, map/manager code and historical
experiment integrations. Their presence does not mean every legacy entry point is
supported or sandboxed in 0.2. The external Battlestation capability engine is not
bundled and its tests skip unless that dependency is explicitly supplied.

[Architecture history](docs/ARCHITECTURE.md) · [Cairn](docs/CAIRN.md) · [Release contract](docs/RELEASE-0.2.md)
