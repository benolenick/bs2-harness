# Lenz v3 boundary

Lenz separates three trust zones:

1. The supported manager-in-the-loop harnesses register through
   `manager/lenz_harness.py`. Both `run_htb.py` and the legacy `run_deep_deepseek.py` harness
   keep their native telemetry formats and create a separate safe mirror containing counts,
   booleans, closed enums, and fixed-template plain-language translations. The mirror accepts no
   free-form translation text at all: the trusted projector renders readable sentences from
   counts, booleans, and enums, so commands, targets, secrets, and model prose have no input path.
   Unknown native events stay
   native-side and do not break observation. The mirror never copies or links raw run data.
   Registration grants the `lenz` account access and atomically publishes `active-run.ref`.
   Historical shell launchers are not part of this observer contract and must not be presented
   as observable engagements.
2. Root-owned `lenz.service` reads that one run and writes an Ed25519-signed structural
   projection. Source strings are never copied into the projection.
3. Root-owned `/usr/local/bin/lenz` verifies the signature, exact v3 schema, and heartbeat
   before returning the payload to an agent.

The hands model may see dirty command output, but raw model text is never trusted as observer
output. The harness converts status into the closed schema; the projector independently validates
and renders it before signing. `translations` therefore
explains what the manager was fed, chose, and received without exposing executable material.

Agent commands:

```sh
/opt/bs2/bin/lenz latest
/opt/bs2/bin/lenz show lenz-0123456789abcdef
/opt/bs2/bin/lenz verify
```

`latest` and `verify` fail closed if the projector is older than 15 seconds. Historical
`show` verifies authenticity and schema but intentionally does not require freshness. The reader
retains an exact legacy-v2 validator so existing opaque historical references remain readable;
new projections use v3 and include fixed-template `translations`.

Production assets:

- `/usr/local/libexec/lenz-projector` — root-owned ingestion code.
- `/usr/local/libexec/lenz-reader` — root-owned read-only consumer.
- `/etc/lenz/private.pem` — readable only by the `lenz` account.
- `/etc/lenz/public.pem` — verification key.
- `/etc/systemd/system/lenz.service` — boot-level hardened service.
- `~/.codex/requirements.toml` — current Codex raw-run read denial. Gunbelt-specific command
  rules stay under `.codex/rules/`; do not deploy them as a machine-wide requirements file.

Repository copies are development sources. After approved changes, a human/CI operator runs
`pytest -q tests/test_lenz.py`, installs reviewed files, and restarts the service. Codex uses
`lenz verify`; it never invokes the raw-side projector or live runner.
