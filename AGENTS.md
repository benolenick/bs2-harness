# For an AI assistant driving BS2

If you are an AI agent asked to run, set up, or drive this pentest engine, do this FIRST,
before any other command:

```bash
python3 scripts/bs2-doctor --require-hitl --json
```

Parse the JSON. Then:

- **`result": "fail"`** (exit 2) — DO NOT run BS2. Show the operator `report_text` and tell them
  to send it to the maintainer (Ben). Each entry in `checks` has a `fix`; apply the ones you can
  (install a package, set an env var, start the broker), then re-run the doctor. Do not work around
  a failure you cannot explain — surface it.
- **`result": "warn"`** (exit 1) — safe to proceed. Skim `checks` for any `warn` the operator would
  care about (a missing tool a lane needs, an unset model key) and mention it.
- **`result": "ok"`** (exit 0) — proceed.

Re-run the doctor whenever the environment changes (new key, new target, broker restarted).

## How BS2 is meant to run (human-in-the-loop, like the MIT harness — but governed)

1. The operator wants **HITL always**: every command that touches the target waits for their
   `y`/`n`. Keep `BS2_REQUIRE_HITL=1` set — the door then refuses to run at all if approval is
   unwired, so you can never accidentally run ungoverned.
2. Start the broker (`live/broker/bs2_cli_broker.py`) and the approver (`live/broker/bs2_gate.py`
   for an interactive human, or `live/broker/servicer.py` for a policy). Commands queue there until
   approved.
3. Run the engine: `python3 live/autocannon.py --target <host>`. It picks + sequences + verifies;
   the trooper model runs each command through the one governed door. You reason, the operator
   approves, the engine follows up on grounded facts.
4. Pointing at a webapp the operator set up? The AI trooper refuses loopback + LAN by default
   (safety). Set the scope opt-in for the authorized target, or every AI-improvised command is
   silently refused (the recipe floor still runs, so it looks half-broken):
   - `127.0.0.1`/`localhost`: `GB_ALLOW_LOOPBACK=1` and `GB_CHARTER_PORTS=<ports>`
   - LAN IP (`192.168.x`): `GB_ALLOW_TARGET=1`
   - any other IP: nothing needed.
   The doctor's `scope-target` check reports exactly which of these is missing.

Never point BS2 at a host the operator is not authorized to test. The doctor and the door enforce
scope, but you are the first line.
