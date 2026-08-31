# BS2 — Governed, Human-Gated Pentest Harness

An autonomous penetration-testing engine where **every command that touches a
target passes through a governed door and waits for a human's approval.** It runs
headless (backend only, no web UI) and is model-agnostic: the "trooper" that
authors and runs on-target commands can be a local LLM, a hosted API, or anything
that speaks the OpenAI chat format.

Think of it as an autonomous recon→exploit loop with a hard **human-in-the-loop
gate on every packet**.

## Why this exists

Autonomous pentest agents are capable but hard to trust: they will happily fire
whatever they decide next. BS2 keeps the autonomy but puts a deterministic,
fail-closed gate in front of the one thing that matters — contact with the target:

- **Every** target-touching command is intercepted at a single door (`target_exec.py`).
- The door enforces, in order: a destructive-command block, a scope/allowlist check,
  then a **per-command operator approval** — then, and only then, execution.
- Deny, timeout, a missing approver, or any error all **fail closed** (no execution).
- The operator sees the exact command, resolved IPs, and action class for each one.

## Architecture

```
 manager (autocannon.py)      authors lanes/objectives, drives the engagement
        │
        ▼
 trooper (trooper.py)         an LLM as the on-target hands (ReAct, one bash block/turn)
        │  + recipes.py       deterministic recon/exploit lanes (no LLM needed)
        ▼
 governed door (target_exec.py)   THE single target-contact primitive
        │   1. destructive-command block   2. scope/allowlist   3. operator approval
        ▼
 approval broker (broker/)    holds each command until a human decides
        │
        ▼
 operator                     approves/denies each command (bin/bs2-gate)
```

Nothing reaches the target except through `target_exec.run()`, and nothing runs
there without passing the broker.

## Quickstart

```bash
# 1. Define scope (only these hosts may ever be contacted)
cp policy.example.json policy.json     # edit allowed_hosts to your target
export BS2_GOVERNANCE_POLICY="$PWD/policy.json"
export BS2_TARGET="10.129.42.10"       # your authorized engagement target

# 2. Start the approval broker (terminal 1)
export BS2_GOVERNANCE_BROKER_URL="http://127.0.0.1:8129"
bin/bs2-broker

# 3. Sit at the gate — you approve every command here (terminal 2)
export BS2_GOVERNANCE_BROKER_TOKEN="$(cat ~/.local/state/bs2-broker/token)"
bin/bs2-gate

# 4. Point the trooper at a model and run the engine (terminal 3)
export BS2_GOVERNANCE_BROKER_TOKEN="$(cat ~/.local/state/bs2-broker/token)"
export TROOPER_BASE="http://127.0.0.1:8000/v1"   # any OpenAI-compatible endpoint
export TROOPER_MODEL="your-model"
python3 autocannon.py --target "$BS2_TARGET"
```

Every command the engine wants to run against the target now appears at your
`bs2-gate` prompt. Press `y` to approve, `n` to deny — one key per command.

## Human-in-the-loop modes

- **`bin/bs2-gate`** (default): interactive. Each target-touching command blocks
  showing the exact command + context; you approve/deny each. `a` = approve the
  rest of the session, `q` = deny and close the gate.
- **`bin/bs2-approve list|allow|deny <id>`**: scriptable decisions.
- **`broker/servicer.py`**: an unattended policy that auto-approves in-scope,
  non-destructive commands and holds anything suspicious — for CI/lab runs only.

## Trooper backends (pluggable)

Any OpenAI-compatible chat endpoint works. Set `TROOPER_BASE` / `TROOPER_MODEL`
(and `TROOPER_KEY_FILE` for hosted APIs). A **local** model is recommended for the
on-target executor: it keeps target content off third-party services, and some
hosted models' safety systems will refuse live-target security content.

## Safety model

- Single target-contact primitive; a destructive-command guard that is always on.
- Scope is re-checked at command time against an allowlist (`deny` / `loopback_only`
  / `scope_only`); an out-of-scope host embedded in a command is rejected.
- Per-command approval token is payload-bound, single-use, and time-limited.
- Runtime policy/state live under `~/.local/state` (0700/0600) and fail closed on
  unsafe permissions. An append-only audit line is written per target command.

## Authorized use only

For authorized security testing, CTFs, and lab/training targets you own or have
explicit written permission to test. You are responsible for staying in scope and
in compliance with the law. No warranty; see LICENSE.
