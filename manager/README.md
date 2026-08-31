# autoturret manager surface

The missing bridge: turns the Opus **manager** from a hand-cranked flat-file poker into a
session with **first-class tools** over the autoturret engine. Before this, the manager had
to `cat recon.json` / run `monitor.sh` to see anything and hand-edit three loose files to
steer. Now it reads a scrubbed **StatusPacket** and pulls the three levers via tool calls.

```
manager (Opus)  ──tools──▶  manager_mcp.py ──▶ manager_bridge.py ──▶  $ATRUN/{recon,levers}
                              (MCP stdio)         (typed, content-blind)      autoturret.py
```

## What's here

| file | role |
|---|---|
| `manager_bridge.py` | Core: typed `StatusPacket` / `Directive`, lever writers, content-blind status builder, **CLI**. Zero deps. |
| `manager_mcp.py` | MCP stdio server exposing the surface as callable **tools**. Zero deps. |
| `../.mcp.json` | Claude Code project registration (start a session in `/opt/bs2`). |

## The tools (what the manager model calls)

- `manager_status` — content-blind snapshot: owned, stop reason, fired/hits/flags, apps→vhost,
  unlocked keys, grounded non-secret facts, **captured-secret counts (values withheld)**,
  current lever state, review-queue count, staleness/liveness warnings.
- `manager_set_goal` — **Lever 2**: planner goal (`rce`, `rce_as:drupal`, `root`, `read_file:/etc/passwd`).
- `manager_hold` — **Lever 1**: pause/resume sweeps.
- `manager_add_directive` — **Lever 3**: append abstract strategy injected into every trooper objective.
- `manager_review_queue` — the unverifiable-claim handoff worklist (safe fields only).
- `manager_which_run` — which run dir the tools act on.

## Content-blindness (enforced here, not just trusted)

`manager_bridge` re-applies the engine's own `SENSITIVE_KEYS` scrub (kept in sync with
`live/autoturret.py:34`; a drift check is in the tests). A fact whose key is
`flag/cred/hash/…` surfaces as a **count** (`flag×2`), never its value. The `evidence`
field of `proven_facts`, the operator feed (`autoturret.ops.jsonl`), and `raw/*.txt` are
**never read**. Verified: `HTB{…}` / `admin:hunter2` cannot come back through any tool.

## Register with Claude Code

A `.mcp.json` already sits at `/opt/bs2/.mcp.json`. Start the manager session from
that directory and approve the `autoturret-manager` server when prompted. Or add it explicitly:

```
claude mcp add autoturret-manager -- python3 /opt/bs2/manager/manager_mcp.py
```

## CLI (works today, no MCP needed)

```
python3 manager/manager_bridge.py status                 # human-readable StatusPacket
python3 manager/manager_bridge.py status --json
python3 manager/manager_bridge.py which                   # active run dir
python3 manager/manager_bridge.py goal rce_as:drupal      # Lever 2
python3 manager/manager_bridge.py hold on|off             # Lever 1
python3 manager/manager_bridge.py directive "prioritise dev.* for source/cred leaks"   # Lever 3
python3 manager/manager_bridge.py review                  # handoff worklist
```

All commands accept `--run-dir DIR`; without it the newest active run is auto-selected.

## The typed protocol objects

`StatusPacket` and `Directive` (in `manager_bridge.py`) are the real, code-backed versions of
the objects the "Calcifer's Ladder" design described but never implemented. They are the
schema the manager↔engine link speaks. Not yet implemented from that design: `ExecutionReport`
(engine→manager per-directive outcome) and a `CompletionDecision` object — today completion is
still the engine's `owned`/`CAPTURED` signal, surfaced in the StatusPacket. Next increments:
a `manager_dispatch_trooper` tool (the engine auto-dispatches troopers today; a manager-driven
one-off would need an engine seam) and wiring an `ExecutionReport` back-channel.

## Wired into Battlestation 2.0 (:8124)

`bs2_client.py` connects the surface to the governed server. BS2's `POST /api/levers` already
carries the same three actions (`set_goal`/`set_hold`/`set_directives`) and its `apply_lever`
writes the **same atrun flat files** the engine reads **plus** a hash-chained `levers.audit.jsonl`.
So the bridge routes each lever **through :8124** when it's steering the atrun BS2 governs
(`realpath(run_dir) == realpath(BS2_TELEMETRY_DIR)` and the server is reachable) — making every
steer both **governed** (ledger event + audit chain) and **effective** (the file the engine obeys).
Falls back to a direct file write when :8124 is down, or when `MANAGER_LEVERS_DIRECT=1`.

- Lever results now carry `"via": "bs2:8124" | "direct-file"` and `"governed": true`.
- `manager_status` gains a `governed` block: server health (`live_tool_execution`, event store,
  witness), battle list, optional battle snapshot (`BS2_BATTLE` env), and this run's `lever_audit` tail.
- Auth: loopback-only + exact same-origin; the client sends the required `Host`/`Origin`. No charter
  attestation is needed for levers (that gates campaign advance / live execution).

Env: `BS2_URL` (default `http://127.0.0.1:8124`), `BS2_TELEMETRY_DIR` (must match the server's),
`BS2_BATTLE` (optional battle to summarise), `MANAGER_LEVERS_DIRECT=1` (force direct writes).

### Web-cockpit DRIVE routes (:8124) — live

BS2's governed server now exposes the two DRIVE primitives as HTTP routes, so the browser
cockpit fires tools too (not just the MCP session). Both delegate to `manager_bridge` — one
content-blind source of truth for the web routes AND the MCP tools:

- `POST /api/fire` {idempotency_key, [goal], [dial], [ttl]} -> fires one engine sweep now
  (non-blocking; reports already-firing if the loop owns the run dir). Returns the safe result.
- `POST /api/dispatch` {objective, idempotency_key, [target], [model]} -> runs one trooper in a
  daemon thread, returns **202** immediately; the scrubbed outcome lands in `manager_actions.jsonl`
  / the telemetry feed (a trooper can take minutes, so the handler never blocks).

Same auth as `/api/levers`: loopback-only + exact same-origin + idempotency key. Content-blind:
no raw output/evidence/secret value is ever returned. Server code:
`battlestation/server.py` (`_handle_post`), lazy-imports `manager_bridge` via `GB_MANAGER_DIR`.

**Known seam:** the double-barrel launcher's governed ledger (`setup_battle.py`) writes a
different DB than the one :8124 serves, so the live run's battle isn't in :8124's battle list —
but the lever audit chain lives in the atrun and IS surfaced. Unifying those DBs is a launcher
change, flagged separately.

**Still to wire:** the browser buttons for these two routes (the routes + MCP tools work today;
the #mgrtel panel doesn't yet render Fire / Dispatch controls).

## DRIVE — the manager fires tools (not just steers)

The three levers *steer* the autopilot. These two tools make the manager the **driver**: it
issues on-target work directly and fires the engine on demand. Both are content-blind.

- `manager_dispatch_trooper(objective, [target], [model])` — **tell a trooper what to do NOW.**
  You write the concrete task (which tool/technique, against which host/path); one trooper runs
  it on-target and returns *manager-safe* results: scrubbed telemetry `{observed,tried,blocked,next}`,
  safe fact strings, and secret-fact **key counts** (values withheld). Raw output & the `evidence`
  value never return. You direct; the trooper issues the commands (manager-only guardrail intact).
- `manager_fire_autoturret([goal], [dial], [ttl])` — **fire the engine NOW.** One bounded, proof-gated
  card sweep against the run's target. If the double-barrel loop is already sweeping this run dir it
  will **not** stack a duplicate — it ensures the engine isn't held and reports the in-flight run.
  Operator-tier stdout goes to a log file (path only, never to the manager).

CLI: `manager_bridge.py dispatch "<objective>" [--target IP] [--model NAME]` and
`manager_bridge.py fire [goal] [--dial full|semi|manual] [--ttl N]`.

Every dispatch/fire is appended (scrubbed) to `manager_actions.jsonl` in the run dir, so the
cockpit shows what the manager did, when. Content-blindness is enforced, not trusted: the scrub
regexes and `SENSITIVE_KEYS` are drift-checked against `live/autoturret.py` in the self-test.

## → Full operating manual: `MANUAL.md`
Web DRIVE console (buttons for status / fire / dispatch): **http://127.0.0.1:8124/drive**
(standalone page — does not touch the main cockpit UI). Full playbook, controls, and governance
in [MANUAL.md](MANUAL.md).
