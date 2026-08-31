# Autoturret Manager Cockpit — Operating Manual

**What this is.** A cockpit where *you (the Opus manager) drive the attack*. You are fed
sanitized telemetry, you tell troopers what to do, and you fire the autoturret engine — the
engine is the autopilot underneath, not a black box. Everything you see is **content-blind**:
flags / creds / hashes never reach you; captured secrets appear as *key counts* only
(`flag×2`), never their values.

```
        ┌──────────── you: the manager (Opus) ────────────┐
        │  read StatusPacket → steer (3 levers) → DRIVE    │
        └───────┬───────────────┬───────────────┬──────────┘
   web console  │   MCP tools    │      CLI      │   ← three ways to reach the same controls
   /drive       │ (session)      │ (terminal)    │
        └───────┴───────┬────────┴───────────────┘
                 manager_bridge.py  ── one content-blind source of truth ──▶ atrun files
                        │                                                       │
                 autoturret.py (engine) ── proof-gated card sweep ── deepseek troopers ──▶ target
```

There are **three surfaces**, all wired to the same primitives — pick whichever fits:

| Surface | Where | Best for |
|---|---|---|
| **Web console** | `http://127.0.0.1:8124/drive` | eyeballing a run + one-click fire/dispatch |
| **MCP tools** | your Claude session (`.mcp.json` in `/opt/bs2`) | you reasoning over results in-context |
| **CLI** | `python3 /opt/bs2/manager/manager_bridge.py …` | scripting / quick checks in a terminal |

---

## The controls (same everywhere)

**READ**
- **Status / telemetry** — target, owned?, fired/hits/flags, apps→vhost, unlocked capability keys,
  grounded non-secret facts, **captured-secret key counts**, current lever state, stop reason.
  MCP `manager_status` · CLI `status` · web: the *Trial status* panel + `GET /api/telemetry`.

**STEER (the 3 levers — nudge the autopilot)**
- **Goal** (lever 2) — the planner aim: `rce`, `rce_as:drupal`, `root`, `read_file:/etc/passwd`, `flag`.
  MCP `manager_set_goal` · CLI `goal <g>` · route `POST /api/levers {action:set_goal}`.
- **Hold** (lever 1) — pause/resume sweeps. MCP `manager_hold` · CLI `hold on|off`.
- **Directives** (lever 3) — abstract standing strategy injected into *every* trooper objective.
  State intent (which surfaces/techniques to prioritise); the trooper picks exact commands.
  MCP `manager_add_directive` · CLI `directive "<text>"` / `set-directives "<text>"`.

**DRIVE (you fire tools directly)**
- **Dispatch a trooper** — write a *concrete* task ("gitlab.*: register, enumerate projects for
  hardcoded creds"); one trooper runs it on-target and returns manager-safe telemetry
  (observed/tried/blocked/next) + safe facts + secret-key counts. **You direct; the trooper issues
  the commands.** MCP `manager_dispatch_trooper` · CLI `dispatch "<objective>"` · `POST /api/dispatch`.
- **Fire the engine** — one bounded proof-gated card sweep now. Won't stack a duplicate if the
  double-barrel loop already owns the run. MCP `manager_fire_autoturret` · CLI `fire [goal]` · `POST /api/fire`.

---

## Playbook — driving a run end-to-end

1. **See where you are.** `manager_status` (or open `/drive`). Note `owned`, `stop reason`,
   `fired/hits/flags`, unlocked keys, and the grounded facts. `stop reason = "frontier dry"` means the
   engine fired every card its current facts unlock and needs *new facts* to continue.

2. **When frontier-dry, produce new facts** — the lever that does this is a **directive** (it changes
   what troopers do), or a **dispatch** (a targeted probe now). Point at the highest-value unexplored
   surface, e.g. for inlanefreight.local: *dev.\* exposed `.git`/backups → GitLab signup + repo secret
   hunt → recursive anon-FTP pull*. Abstract in the directive; concrete in a dispatch.

3. **Set the goal to match the opening** you're chasing (`set_goal rce_as:git`, `root`, …). The planner
   re-plans on the next iteration toward that aim.

4. **Fire** if the loop isn't already sweeping (`manager_fire_autoturret`), or just let the
   double-barrel loop pick up your levers on its next iteration.

5. **Watch the ceiling, not the churn.** Each cold restart is a fresh trial from zero — that's the
   **baseline that measures whether we're improving**, by design. The number that matters is how far a
   trial gets (max proven, foothold keys like `shell`/`session`, `owned`). Don't read a reset to
   baseline as regression.

6. **Escalate** once a foothold key (`shell`, `session`, `rce_as:*`) grounds: `set_goal root`, and
   dispatch post-foothold enumeration (sudo -l, cron, SUID, creds reuse across hosts).

---

## Running the live rig (double-barrel loop)

```
/opt/bs2/live/run_double_barrel.sh <TARGET_IP> [RUN_MINUTES]
```
Stands up the atrun at `/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria/atrun`, the warroom UI, the
escalation ladder, and a hands-loop that re-fires `autoturret.py` per iteration. **It wipes
`campaign.sqlite3` each iteration on purpose** — cold restart is the control. Your levers/dispatches
act on that atrun; the governed server (:8124) reads/writes the same files and hash-chains each lever.

---

## Governance & safety (what's enforced, not trusted)

- **Content-blindness.** `manager_bridge` re-applies the engine's `SENSITIVE_KEYS` scrub and secret
  regexes (drift-checked equal to `live/autoturret.py` in the self-test). It never reads
  `autoturret.ops.jsonl`, `raw/*.txt`, or the `evidence` field. The web routes return only scrubbed
  results; operator-tier engine stdout goes to a log file (path only).
- **Manager-only guardrail (live targets).** You direct and verify; the engine and deepseek troopers
  issue the on-target commands. Dispatch = you writing the objective, the trooper running it.
- **Governed writes.** `POST /api/levers|/api/dispatch|/api/fire` are loopback-only + exact same-origin
  + idempotency-keyed; levers are hash-chained into `levers.audit.jsonl`; every fire/dispatch is
  appended (scrubbed) to `manager_actions.jsonl` so the cockpit shows what the manager did.

---

## Files

| Path | Role |
|---|---|
| `manager/manager_bridge.py` | content-blind core + CLI (status, levers, **dispatch, fire**) |
| `manager/manager_mcp.py` | MCP stdio server — 8 tools |
| `manager/bs2_client.py` | client to the governed :8124 server |
| `.mcp.json` | Claude Code registration (start a session in `/opt/bs2`) |
| `battlestation/static/drive.{html,js,css}` | the standalone web DRIVE console (`/drive`) |
| `battlestation/server.py` | governed server; `/api/dispatch` + `/api/fire` in `_handle_post` |
| `…/bs2-memoria/atrun/` | the run dir: recon.json, levers, telemetry_feed.json, manager_actions.jsonl |

## Quick reference

```
# CLI
python3 manager/manager_bridge.py status
python3 manager/manager_bridge.py goal rce_as:git
python3 manager/manager_bridge.py directive "prioritise dev.* .git + gitlab signup for creds"
python3 manager/manager_bridge.py dispatch "gitlab.inlanefreight.local: register, enumerate projects/snippets for DB creds + CI tokens"
python3 manager/manager_bridge.py fire root --ttl 900

# Web console
xdg-open http://127.0.0.1:8124/drive
```
