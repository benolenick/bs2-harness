# BS2 Control-System Critique

**Scope:** BS2, Gunbelt, Ariadne, Cartographer, Autoturret, the manager/trooper loop,
governed execution, evidence, escalation, Lenz, and the Jagg execution host.

**Assessment date:** 2026-08-25

**Observation boundary:** This assessment is based on source code, project manifests,
offline tests, the installed Jagg tool inventory, and the signed Lenz projection. No raw
engagement artifacts were used. Lenz was healthy and signature-valid but reported
`no_active_run`, so this document assesses the system design and current code rather than
claiming what the unobserved live engagement did.

## Executive judgment

BS2 is not supposed to be simple. A serious autonomous pentest platform must coordinate
authorization, discovery, planning, tactical execution, evidence, post-exploitation,
recovery, memory, and observation. The problem is not that BS2 has many organs. The problem
is that several generations of those organs coexist and sometimes perform the same job.

The project contains strong individual ideas:

- an event-sourced governance core;
- a durable discovery and environment map;
- an attack-path planner that distinguishes facts from assumptions;
- a content-blind strategic manager;
- cheaper target-facing hands;
- a reusable recipe corpus;
- a large tool host on Jagg;
- evidence verification, completion accounting, escalation, and a safe observer boundary.

The system is not yet coherent enough to trust unattended because it currently has multiple
launchers, schedulers, recipe engines, state stores, planning cadences, and execution paths.
The same engagement can behave differently depending on which entry point launched it.

The required outcome is not to remove the sophistication. It is to establish one
authoritative control model:

> One witnessed event graph, several specialized projectors and advisors reacting to explicit
> state transitions, one scheduler admitting work, and one governed executor applying it.

## 1. The intended control system

```text
Human-attested battle charter and scope
                  |
                  v
        Authoritative BS2 event ledger
                  |
       +----------+-----------+
       |                      |
       v                      v
Cartographer projection   Evidence/coverage projection
surface + environment     findings + cleanup + completion
       |
       +----------+------------------+
                  |                  |
                  v                  v
      discovery frontier       Ariadne fact graph
      what remains unknown     routes + useful unknowns
                  \                  /
                   \                /
                    v              v
                  Manager objective
                         |
                         v
        Trooper + recipes + available Jagg capabilities
                         |
                         v
        Policy broker and governed executor on Jagg
                         |
                         v
        Raw result -> verifier -> accepted evidence event
                         |
                         +-----------> repeat
```

The feedback loop is the product. No single module owns the engagement by itself.

## 2. The four different frontiers

Several current documents use the word `frontier` for different things. They must remain
separate, although they are related.

### 2.1 Discovery frontier — Cartographer

The discovery frontier answers:

> What surfaces have been discovered, and which standard survey obligations remain?

Examples include an unenumerated web port, an unexplored virtual host, an unlisted share,
an unknown identity, or post-foothold local/network enumeration. Cartographer ranks this
work by coverage value and state. It does not decide which exploit to use.

### 2.2 Attack frontier — Ariadne

The attack frontier answers:

> Given accepted facts and negatives, what paths could reach the goal, and which observable
> unknown would unlock the most progress?

Ariadne returns operators, paths, assumptions, and confirmation targets. It does not choose
a shell command, authorize an action, or touch a target.

### 2.3 Execution frontier — scheduler and policy broker

The execution frontier answers:

> Which proposed work is eligible to run now, given scope, dependencies, capabilities,
> concurrency, rate limits, risk, budget, leases, cleanup, and prior attempts?

Neither Cartographer nor Ariadne owns this decision. This is the missing single scheduling
authority that competing launchers currently approximate in different ways.

### 2.4 Evidence frontier — verifier and completion controller

The evidence frontier answers:

> Which claims remain unverified, which hypotheses need testing, which negative conclusions
> are supported, and what prevents honest completion?

This prevents a successful command, a model narrative, or a discovered flag from silently
becoming a confirmed finding or a completed engagement.

## 3. Ariadne: what it knows and when it should run

Ariadne is an advisory reasoner. It receives:

- accepted target facts;
- accepted confirmed negatives;
- one bound goal;
- a target-independent operator corpus.

Its backward planner first searches for fully grounded paths. If none exist, it returns
near paths whose leaves are observable assumptions. It refuses to satisfy an action outcome
merely by assuming that outcome. Its forward recon planner estimates which observable fact,
if confirmed, would unlock the most goal-relevant state.

That core model is sound. Ariadne should run whenever the authoritative planning input changes:

- a verified fact is accepted or retracted;
- a confirmed negative is accepted or retracted;
- a target generation changes;
- scope or goal changes;
- a new host, session, identity, credential reference, or surface becomes reachable;
- an attempt changes the status of a hypothesis or route.

It should not run because a fixed timer elapsed, and it should not fire anything. A planner
result should be stamped with the exact battle head, target generation, fact-set digest,
negative-set digest, goal, and operator-corpus digest. A stale result is advisory history,
not executable work.

### Current Ariadne cadences

The code currently invokes Ariadne through several independent loops:

1. `manager/run_htb.py` recomputes six hard-coded goal rungs on every manager step and asks
   for recon guidance on the first two unmet rungs.
2. `live/autoturret_planner.py` replans for up to eight planner-tail steps and maps the first
   operator to a hard-coded lane.
3. `live/reflex_loop.py` replans several fixed open goals whenever new findings arrive.
4. The web mapper builds per-class plans while constructing its worklist.

These loops can use different facts, negatives, goals, and state stores. Ariadne itself is
not the conflict; the absence of one authoritative planning snapshot is.

### Goal-shape problem

The current manager advisory ladder assumes targets shaped like a Linux/AD exercise:
`www-data`, `/root/root.txt`, `domain_admin`, and `dc`. These may be useful goal profiles,
but they are not universal defaults. Goals should come from the battle charter and current
terrain, with explicit profile selection for web assessment, host ownership, AD control,
flag retrieval, or another authorized outcome.

## 4. Cartographer: projector, not shooter

Cartographer should be a deterministic, event-driven projection of accepted evidence. It
should never execute a tool. Its responsibilities are:

- maintain external and post-foothold topology;
- represent hosts, ports, applications, endpoints, shares, users, identities, sessions,
  credential references, pivots, and internal reachability;
- track discovery obligations independently from access and attack outcomes;
- maintain durable vulnerability hypotheses and their evidence status;
- expose ranked discovery work and honest completion blockers;
- produce a versioned Ariadne fact projection.

### Correct cadence

Cartographer should fold immediately after an accepted event changes relevant state. The
frontier should then be a pure query over the new projection. It does not need a polling
frequency and does not independently "fire."

Survey workers may subscribe to newly eligible discovery work. Their activity must still be
admitted by the scheduler and executed through governance.

### Current behavior

- The primary manager loop folds trooper facts after each `TASK` and recalculates the frontier
  once per manager turn.
- `hands.py loop` is a separate driver that takes the top frontier item, runs its mapped survey
  rituals, and repeats for up to six rounds.
- The separate hands path directly uses SSH to Jagg rather than governed dispatch.
- Some UI/terrain projections refresh on timers, but projection refresh is not new survey work.

Cartographer is therefore continuously readable, not continuously and coherently surveyed.

### Current correctness risks

- lifecycle transitions fuzzy-match free-text hints to nodes;
- malformed observation translation may fail soft and silently lose information;
- a zero exit code can mark a ritual covered without proving substantive coverage;
- a generic foothold is projected back into Ariadne as `shell=www-data`;
- discovery coverage, access, route outcome, and exhaustion are still too easy to collapse
  into one lifecycle state;
- the Cartographer ledger is not yet the canonical BS2 Terrain projection.

## 5. Autoturret: three incompatible meanings

`Autoturret` currently names several different behaviors.

### 5.1 Concurrent floor scheduler

This is the valuable behavior: run safe, authorized, independent discovery work concurrently;
when verified facts unlock another safe action, schedule it immediately within rate and
capability budgets.

### 5.2 Autonomous recipe and planner engine

In Double Barrel, Autoturret starts immediately at `full` dial. Its internal scheduler can
run eight lanes concurrently, submit newly eligible lanes as soon as a fact lands, perform a
large catalog sweep after the floor, and then let an Ariadne adapter select and fire a
hard-coded operator lane. One invocation can run for 1,500 seconds, and the outer script
restarts it until the engagement deadline.

This is not "peeking up" after a meaningful trigger. It begins ballistic and stays eligible
to restart until held, owned, or out of time.

### 5.3 Event-triggered reflex

The reflex loop is closer to the right design. It examines newly verified findings, derives
planning facts, requires attested provenance and a severity threshold before arming a predicate,
checks the risk ceiling, and fires each eligible card once.

The remaining flaw is that the reflex cards themselves contain target-shaped, hard-coded
procedures. The wake condition is promising; the work unit must become a reviewed bounded
procedure or trooper objective rather than an embedded solve.

### Correct wake policy

Autoturret should wake only when all of the following are true:

1. an authoritative state transition creates newly eligible work;
2. the work belongs to a reviewed safe-floor action or an explicitly authorized procedure;
3. its preconditions are evidence-backed and bound to the current target generation;
4. a current capability exists on an execution host with the required network position;
5. policy, risk, rate, concurrency, budget, TTL, and cleanup checks pass;
6. no equivalent work is active, complete, or negatively resolved;
7. the work is admitted by the one scheduler and receives a single-use execution lease.

A stall timer may wake the manager, ask Ariadne for a new projection, request research, or
escalate to the operator. It must not independently authorize more aggressive target actions.

## 6. Escalation behavior

The Double Barrel escalation ladder polls every 30 seconds. A progress fingerprint changes
when owned hosts, flags, credentials, fact-file size, or phase changes. Tool calls alone do not
count. After each seven-minute stall window it advances through:

1. replan toward a relaxed goal;
2. second opinion;
3. research;
4. operator escalation.

This is a useful anti-thrashing concept. Its current relationship to Autoturret is weak,
however: Double Barrel is already running Autoturret at full dial while the ladder merely
writes advice. In no-operator mode it can remain at the research rung and re-trigger it.

Escalation should change one explicit control state in the authoritative ledger. Examples are
`manager_wake_requested`, `research_requested`, `goal_revision_proposed`, or
`operator_attention_required`. It should not communicate through a collection of sidecar files
whose meaning depends on the active launcher.

## 7. Recipes and cards

Recipes should be tactical memory consulted by the trooper. A useful recipe contains:

- applicability and required facts;
- the capability or tool family involved;
- a parameterized invocation pattern;
- expected cost and risk;
- success, failure, and indeterminate evidence predicates;
- cleanup requirements;
- known caveats and provenance;
- the Ariadne predicates it may confirm.

A recipe is not independently authorized work. Selection does not grant execution authority.
Verification after execution cannot replace authorization before execution.

### Current catalog condition

The active deck contains 612 unique cards and 169 distinct tool labels. At the assessment
snapshot:

- 354 success criteria were deterministically indeterminate;
- 450 cards lacked an Ariadne operator join;
- 158 lacked `confirms` relationships;
- 110 emitted no facts;
- the authoring gate rejected three active cards and warned on 463;
- some tool labels were unavailable binaries, generic placeholders, or pseudo-tools.

The large deck is therefore an authoring corpus, not a production-ready capability set.

### Current executable recipe engines

`live/recipes.py`, the catalog bridge, Autocannon, Autoturret, Closer, reflex cards, and new
`live/cards` modules all provide ways for stored logic to become executable behavior. Turning
recipe-first off by default in one manager path is useful containment, but it does not remove
those alternative controllers.

## 8. Jagg: arsenal versus capability

Jagg has a genuinely broad arsenal. The observed inventory included:

- network and web discovery: Nmap, FFUF, Gobuster, Feroxbuster, Nuclei, Katana, httpx,
  WhatWeb, Nikto, WPScan, and DNS/SMB utilities;
- application testing: SQLMap and related web tooling;
- Windows and AD: NetExec, BloodHound, Impacket, LDAP, RPC, and SMB clients;
- credentials: Hydra, John, Hashcat, and password auditing utilities;
- exploitation and research: Metasploit and Searchsploit;
- pivoting and transport: Chisel, ProxyChains, Socat, SSH, and netcat;
- approximately 2.5 GB of SecLists plus additional wordlists.

An installed binary is not automatically a BS2 capability. A production capability registry
should record, for every approved tool adapter:

```yaml
capability_id: web.content.discovery
execution_host: your-host
tool: ffuf
path: /usr/bin/ffuf
version: <measured version>
health: ready
network_zones: [htb-vpn]
input_schema: <typed objective inputs>
action_classes: [web.recon]
risk: readonly
side_effects: [network.requests, local.artifact.create]
rate_model: <requests/concurrency limits>
evidence_parser: <versioned parser>
cleanup: <declared obligations>
adapter_digest: <immutable digest>
last_verified: <timestamp>
```

The scheduler should match an admitted objective against this registry. The trooper should see
only currently applicable capabilities, not every binary on the machine. The manager may see
abstract categories and readiness, but does not need raw tool paths or commands.

### Current Jagg integration

- `hands.py` knows only ten hard-coded discovery mappings despite the much larger arsenal.
- It executes those mappings by direct SSH, outside the single governed receipt path.
- The catalog names far more tools than have healthy adapters or installed binaries.
- Double Barrel explicitly unsets `TROOPER_EXEC_SSH`, causing its target actions to run on
  Kaloth while Jagg primarily supplies memory retrieval.
- The Jagg Gunbelt copy is a partial, divergent deployment rather than a versioned release of
  the Kaloth source tree.

Jagg should become the declared execution plane, not an occasionally used remote shell.

## 9. Current trigger and cadence matrix

| Controller | Trigger today | Frequency/bound | What it can cause |
|---|---|---:|---|
| `run_htb` manager | next manager step | up to 30 steps by default | one trooper objective, plus map/fact fold |
| `run_htb` Ariadne advisory | every manager step | six goals; recon on two unmet goals | manager guidance |
| Cartographer projection | after a returned `TASK` result | once per task | map, frontier, hypotheses, coverage |
| `hands.py loop` | manual/separate invocation | top one node, up to six rounds | sequential direct-SSH survey actions |
| Autoturret scheduler | Double Barrel starts it | up to eight concurrent lanes, 1,500-second iteration | recipes/trooper lanes and immediate unlocks |
| Double Barrel outer loop | previous Autoturret iteration ends | repeats until engagement deadline | another full-dial Autoturret run |
| catalog sweep | floor scheduler drains | up to four rounds | terrain-matched card execution |
| Autoturret planner tail | catalog/floor phase ends | up to eight steps | hard-coded operator-to-lane execution |
| reflex loop | L3 dispatch ends or manual call | up to three rounds | attested predicate cards |
| escalation ladder | no progress fingerprint change | polls 30s; climbs every 420s | replan/research/opinion/operator advice |
| UI/terrain promotion | launcher-specific timers or completion | commonly four-second projection refresh | presentation/projection only |
| Lenz projector | active manager pointer | approximately two-second projection | signed observer state only |

This matrix explains why the system is difficult to reason about: cadence and authority are
encoded in entry points rather than one explicit scheduler contract.

## 10. Governance and truth defects

The following defects prevent the current composition from being trustworthy even if its
attack logic works:

1. **Execution is not physically exclusive.** Direct Bash, SSH, subprocess, recipe, hands,
   specialist, and launcher paths can touch the target outside one governed adapter.
2. **Approval can be synthesized.** The live seam contains a local `ben` attestation and a
   `gate-approved-local` approval reference rather than requiring a witnessed external human
   authority event.
3. **Post-action verification is confused with pre-action authorization.** Full Autoturret
   mode can bypass recipe disposition and execute manual/high-blast cards before evaluating
   whether they worked.
4. **Evidence binding is weak.** A confirmed hypothesis may be promoted without a non-empty,
   verifier-accepted evidence set bound to the battle, target generation, node, objective,
   command receipt, and artifact digest.
5. **Completion is bypassable.** Missing scope may still permit completion, exhausted surfaces
   do not necessarily prove adequate coverage, and `DONE FORCE` bypasses blockers.
6. **Manager doctrine conflicts.** The project manifest still says the manager authors exact
   commands, while the current hotfix contract and `run_htb` say the manager issues objectives
   and the trooper authors commands.
7. **Live observation is incomplete.** Lenz is healthy but no active-run pointer is published
   for the engagement the operator reports as running.

## 11. One coherent event-driven cadence

The following cadence preserves the system's sophistication while eliminating competing loops.

### On battle activation

1. Witness the charter, scope, goal profile, risk ceiling, target generation, and human authority.
2. Measure the Jagg capability registry and reject unavailable or stale adapters.
3. Start one scheduler and publish the Lenz active-run reference.
4. Seed Cartographer from verified intake, not an optimistic map placeholder.

### On every accepted evidence event

1. Append the event to the authoritative BS2 ledger.
2. Rebuild or incrementally update Cartographer, hypotheses, environment, and completion.
3. If the planning-input digest changed, recompute Ariadne once for the current goals.
4. Derive eligible discovery, validation, exploitation, post-exploitation, cleanup, and retest work.
5. Deduplicate against active, completed, rejected, and expired work.
6. Admit safe-floor work automatically only within the charter's capability lease.
7. Wake the manager when a strategic choice, risk fork, unexpected result, credential, new host,
   foothold, route shift, or stall requires judgment.

### On manager objective

1. Bind the objective to the current battle head, target generation, node/hypothesis, risk, and
   acceptance evidence.
2. Give the trooper the bounded objective, relevant map slice, Ariadne advice, recipes, memory,
   and applicable Jagg capabilities.
3. Let the trooper propose one atomic action or reviewed bounded procedure.
4. Submit it to the policy broker; never execute directly.
5. Execute on the registered host through a single-use lease.
6. Keep raw output on the execution/evidence side and return only verified structured results.

### On stall

1. Confirm the state digest truly has not advanced; command count is not progress.
2. Ask Ariadne to recompute from the unchanged facts and negatives.
3. Wake the manager with the stalled routes and unresolved evidence frontier.
4. Optionally request bounded research or an independent critique.
5. Escalate to the operator if the configured autonomy ceiling is reached.
6. Never translate elapsed time directly into authorization for riskier actions.

## 12. Convergence plan

### Phase A — Freeze authority and contracts

- Make the objective-only manager/trooper contract authoritative everywhere.
- Define one event schema for facts, negatives, hypotheses, evidence, work, capabilities,
  attempts, cleanup, and completion.
- Make BS2 events the only durable authority; all maps, feeds, cards, and UI state are projections.

### Phase B — Establish one scheduler and one executor

- Choose one production launcher.
- Route manager tasks, survey hands, recipes, specialists, reflexes, and cleanup through one
  scheduler and governed executor.
- Remove or hard-disable every direct target-facing subprocess and SSH path.
- Require real witnessed authorization and single-use capability receipts.

### Phase C — Integrate Cartographer and Ariadne by state version

- Fold only verifier-accepted events.
- Separate discovery coverage, access, attack outcome, and workflow lifecycle.
- Replan once per changed planning digest.
- Bind advice to the exact state version and reject stale proposals.

### Phase D — Make Jagg a measured execution plane

- Generate a signed/versioned capability registry from healthy adapters.
- Deploy one release artifact to Jagg and verify its manifest and hashes.
- Select tools by objective, evidence quality, network position, risk, and cost.
- Treat wordlists, GPU cracking, pivot interfaces, and local privileges as explicit capabilities.

### Phase E — Curate recipes

- Quarantine the 612-card deck as an authoring corpus.
- Promote a small reviewed set with deterministic gates, valid vocabulary, healthy tools,
  cleanup, and offline fixtures.
- Keep recipes consultative unless a reviewed safe-floor procedure is explicitly admitted.
- Keep cross-battle write-back disabled until its poisoning and provenance controls are accepted.

### Phase F — Prove the whole organism

Build one target-free end-to-end scenario that exercises:

1. human authority and scoped battle activation;
2. Jagg capability measurement;
3. verified discovery opening Cartographer frontier work;
4. Ariadne advice changing after a new fact and a confirmed negative;
5. manager objective to trooper proposal;
6. governed admission, execution receipt, evidence verification, and map update;
7. a newly opened post-foothold frontier;
8. an event-triggered safe reflex;
9. denied stale, out-of-scope, expired, duplicate, and high-risk work;
10. cleanup, retest, honest completion, report, and signed Lenz projection.

## 13. Release criteria

BS2 is ready for unattended operation only when all of these are true:

- one documented production launcher exists;
- one scheduler owns work admission;
- every target-touching action has a governed receipt;
- no local code can mint human authority;
- the manager/trooper contract is consistent in code, prompts, tests, and manifests;
- Cartographer derives only from accepted events and cannot invent access identity;
- Ariadne advice is state-version-bound, advisory, and stale-safe;
- Jagg exposes a measured capability registry rather than an unbounded shell;
- recipes cannot become authority merely because their preconditions match;
- high-blast and destructive actions require pre-action authorization at every autonomy level;
- findings require verifier-accepted evidence;
- scope, coverage, cleanup, and unresolved hypotheses fail completion closed;
- Lenz observes the actual production run through its active pointer;
- the target-free end-to-end suite and all core tests are green;
- Kaloth and Jagg run the same versioned release.

## 14. Current verification snapshot

At the time of this assessment:

- critical Gunbelt modules compiled;
- the two focused `run_htb`/Cartographer tests passed;
- the BS2 core suite reported 354 passed, 17 failed, and one skipped;
- eight failures were caused by appended browser code violating the existing Node/DOM test
  contract;
- nine governed-executor tests were blocked because their hard-coded authorization fixture had
  expired relative to the current date;
- Lenz verification reported a current, signature-valid projection but `no_active_run`;
- Jagg held the broad arsenal described above but only a partial, divergent Gunbelt deployment.

These results do not prove that the core governance design is broken. They prove that the
current repository and deployment do not meet a green release gate.

## 15. Final assessment

BS2 is not failing because it attempts too much. It is failing because responsibility and
authority are duplicated across historical implementations.

The correct design retains Ariadne, Cartographer, Autoturret, recipes, memory, the manager,
troopers, Jagg, evidence, escalation, UI, and Lenz. It changes how they relate:

- Cartographer owns projected truth about the terrain.
- Ariadne owns advisory reasoning over that truth.
- The manager owns strategic objectives and exceptions.
- The trooper owns tactical tool choice within a bounded objective.
- Recipes provide reusable tactical memory.
- Jagg provides measured execution capabilities.
- The scheduler owns cadence, deduplication, budgets, and work admission.
- The policy broker owns authorization.
- The executor owns target contact.
- The verifier owns evidentiary acceptance.
- BS2 events own history and authority.
- Lenz owns the agent-safe observation boundary.

That is a complex system, but it is a coherent one. The current task is convergence, not
further feature growth.

## Related documents

- [`BS2-HOTFIXES.md`](BS2-HOTFIXES.md) — implementation-oriented P0/P1 repair program.
- [`BS2-ATLAS.md`](BS2-ATLAS.md) — existing high-level component atlas.
- [`NORTH-STAR.md`](NORTH-STAR.md) — current design intent.
- [`LENZ.md`](LENZ.md) — observer boundary and deployment.
- [`../live/CARTOGRAPHER.md`](../live/CARTOGRAPHER.md) — Cartographer and survey-hands design.
- [`../../ariadne/SIGIL.md`](../../ariadne/SIGIL.md) — Ariadne purpose and planner contract.
