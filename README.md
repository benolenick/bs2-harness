# BS2 — a governed, model-agnostic pentest engine

BS2 is an autonomous penetration-testing engine built around one non-negotiable
idea: **every command that touches a target passes through a single governed door,
and the human operator can approve or deny each one from the command line.**

It is model-agnostic. A capable frontier model (the "manager") authors each command
from a live map of the target; a cheap local model (the "trooper") executes it on the
box. The manager never touches the target directly — it reasons, the trooper triggers,
and the governed door decides whether the trigger fires.

## Why it's built this way

- **Governance is the product.** `live/target_exec.py` is the *only* path to the
  target. Order of gates, all fail-closed: destructive-command block → scope/allowlist
  guard → per-command operator approval → budget → execute. Nothing reaches a box
  around it.
- **Human-in-the-loop, per command.** The broker (`live/broker/`) pauses every
  box-touching command and waits for a decision. Approve interactively at a TTY
  (`bs2-gate`), scriptably (`bs2-approve allow/deny <id>`), or under an unattended
  policy (`servicer.py`). You see exactly what MIT-style harnesses show — the command,
  the target, the action class — and you say yes or no.
- **Model-agnostic executor.** Point the trooper at any OpenAI-compatible endpoint or
  a local CLI (`TROOPER_BASE` / `TROOPER_MODEL` / `TROOPER_KEY_FILE`). The intelligence
  lives in the manager's reasoning each step, never in frozen if-vuln-shape branches.

## What's in here

| Component | Path | Role |
|---|---|---|
| Governed door | `live/target_exec.py` | the single gated path to any target |
| Approval broker | `live/broker/` | HITL gate: interactive, scriptable, or policy |
| Trooper | `live/trooper.py` | on-target executor (any model) |
| Manager | `manager/`, `live/autocannon.py` | authors commands from the live map |
| Cartographer / hands | `live/` | autonomous recon — builds the map itself |
| Ariadne planner | `ariadne/` | attack-path planner the manager consults; advisory, served on `:8112` |
| Catalog | `catalog/deck_final.yaml` | attack-recipe library (a library, never the decider) |
| Scorer | `scorer/` | grounded verification of results |
| Tests | `tests/` | governance + scorer integrity suites |

## Deliberately NOT included

- **No cheat-sheet playbook for the executor.** The trooper is never fed a static
  answer-key — a capable frontier model authors the commands. (The Ariadne *planner*
  under `ariadne/` does ship its own symbolic operator corpus + an offline Exploit-DB
  *index* for path ranking; that is advisory input to the manager, not a trooper playbook.)
- **No frontend.** This is the backend engine only.
- **No secrets, no engagement transcripts.** Bring your own keys and scope.

## Quickstart

```bash
# 1. point the trooper at a model (any OpenAI-compatible endpoint)
export TROOPER_BASE=https://api.your-provider.com/v1
export TROOPER_MODEL=your-model
export TROOPER_KEY_FILE=~/.config/bs2/trooper.key

# 2. start the operator approval gate in a terminal (interactive HITL)
python3 live/broker/bs2_cli_broker.py &     # the broker
python3 live/broker/bs2_gate.py             # the TTY approver — y/n on every command

# 3. (optional) start the Ariadne attack-path planner for path ranking
bash scripts/start_ariadne.sh &             # serves :8112; advisory, safe to omit

# 4. tell the recipe lanes which host is in scope, then run the manager
export BS2_TARGET=198.51.100.10   # recipe-driven lanes gate on this; unset => "outside scope"
python3 live/autocannon.py --target 198.51.100.10
```

Scope lives in a policy file (see `policy.example.json`): set `network_mode` and `allowed_hosts`. Anything outside scope is denied at the door, before approval.

## Authorized use only

BS2 is for **authorized** security testing — engagements you have written permission
to run, CTFs, and lab targets you own. The governed door and per-command approval exist
so a human stays accountable for every action. Don't point it at anything you aren't
allowed to test.

MIT-licensed. Copyright (c) 2026 Ben Olenick.
