# BS2 Hotfix Program

Status: proposed for implementation  
Date: 2026-08-24  
Scope: Kaloth Gunbelt, the BS2 governed core, and the Jagg execution deployment  
Safety posture: offline and synthetic verification only until every P0 exit gate passes

## Outcome

BS2 has strong individual organs, but it does not yet have complete mediation. Several
launchers can execute outside the governed seam, several observation surfaces can bypass Lenz,
and the project currently contains two incompatible definitions of the manager/trooper split.

This program stabilizes BS2 before any additional reconnaissance, exploitation, pivoting, or
write-back capability is added.

## Authoritative operating contract

This contract supersedes the exact-command language currently present in `SIGIL.md`,
`docs/NORTH-STAR.md`, `manager/manager_loop.py`, and older state notes:

1. The manager is the strategist. It receives only a structurally bounded map, proposed routes,
   memory hints, coverage state, and sanitized result markers.
2. The manager never sees raw target output and never authors a shell command.
3. The manager issues one plain-English objective describing what to achieve or determine and,
   when useful, why it is the next move.
4. The trooper is the skilled operator. It selects tools and authors exact commands needed to
   pursue that objective.
5. The trooper cannot execute a command directly. Every command is submitted to the governed
   executor with the current battle, target generation, capability, objective, action class,
   risk, and work-order identity.
6. Only independently verified evidence may change access state, confirm a finding, satisfy a
   completion condition, or enter a report as demonstrated impact.
7. Codex observes active engagements only through Lenz. Human/operator views remain separate.

`manager/run_htb.py` is the closest current implementation of the intended division of labor.
The exact-command `manager_loop.py` path must be retired or explicitly moved into a separately
named, human-only experimental mode. It must not remain a competing north star.

## Emergency containment until the P0s land

- Do not begin a new live engagement through `run_htb.py`, `run_deep_deepseek.py`, Jagg
  `live/run.sh`, or an Autoturret launcher that can call a trooper directly.
- Keep cross-battle recipe write-back disabled.
- Keep specialist dispatch disarmed by default.
- Codex must use only `bin/lenz latest`, `bin/lenz show`, and `bin/lenz verify` for run state.
- Human operators may retain their richer cockpit, raw artifacts, and forensic access, but those
  surfaces must not be reachable from the Codex execution identity.

## H0 — Make Lenz the only Codex observation path

Priority: P0  
Failure addressed: `/api/telemetry` and related feeds expose engagement state outside Lenz.

### Change

- Introduce explicit viewer roles: `human_operator`, `policy_auditor`, `manager_runtime`, and
  `codex_observer`.
- Serve human/operator telemetry through an authenticated endpoint or Unix socket whose
  credential is unavailable to the Codex OS identity.
- Deny `codex_observer` access to `/api/telemetry`, `/api/feed/*`, manager JSON, run directories,
  and any route that returns target, path, marker, fact, command, finding text, or evidence.
- Keep `/api/health` structural: service state, schema version, and integrity state only.
- Make Lenz consume its root-owned signed projection, never an HTTP endpoint shared with the
  cockpit.
- Add a server-side denial. Project instructions and prompt text are supplementary, not the
  enforcement boundary.

### Acceptance tests

- As the Codex identity, every non-Lenz engagement observation path returns a typed denial.
- The human cockpit still receives its authorized view.
- Lenz continues to reject stale, unsigned, malformed, future-dated, and extra-key projections.
- No Lenz payload contains target identifiers, paths, commands, rationales, facts, findings,
  secret values, evidence content, or answer-key labels.
- A repository-wide test enumerates all HTTP/file observation surfaces and proves there is no
  second Codex-readable route.

### Rollback condition

If the cockpit cannot be separated safely, disable its run-telemetry routes and retain only the
health endpoint until role separation is working.

## H1 — Remove the conflicting manager implementation

Priority: P0  
Failure addressed: project doctrine simultaneously says the manager authors exact commands and
that the manager never authors commands.

### Change

- Rewrite the North Star sections in `SIGIL.md`, `docs/NORTH-STAR.md`, manager documentation,
  prompts, and examples to use the authoritative contract above.
- Remove `PROBE`, `LISTIDS`, and other command-shaped manager actions from the default manager
  grammar. The default action is `TASK <plain-English objective>`.
- Deprecate `manager/run_deep_deepseek.py` and `manager/manager_loop.py` as launchable production
  paths unless they are converted to objective-only dispatch.
- Give one module ownership of manager prompt construction and action parsing.
- Reject fenced code, shell syntax, and command-only manager responses before dispatch.

### Acceptance tests

- A test asks the manager to produce shell syntax; parsing rejects it and records no dispatch.
- A normal objective reaches the trooper without being rewritten into a hard-coded technique.
- No production prompt tells the manager to author, select flags for, or run an exact command.
- A repository search finds no second production manager grammar.

## H2 — Make governed execution physically exclusive

Priority: P0  
Failure addressed: `run_htb.py`, Jagg Autoturret, manager bridge dispatch, and specialist paths
can execute commands beside the governed seam. Some paths record harmless receipt commands that
are not the command actually executed.

### Change

- Replace direct `Trooper().fire()` execution with two ports:
  `Trooper.propose_command(objective, sanitized_observation)` and
  `GovernedCommandPort.execute(proposal)`.
- Remove direct calls to `bash`, SSH execution, and `run_cmd()` from trooper-facing production
  paths. Only the governed worker may spawn a process.
- Bind each proposal and receipt to:
  battle ID, charter hash/revision, current event head, target generation, objective digest,
  exact command digest, action class, risk, capability ID, work-order ID, executor identity,
  timeout, and request budget.
- A capability may be issued only from an existing, witnessed human approval event. Reject
  placeholder approval IDs, synthetic `ben` attestations, or approvals that do not resolve in
  the same battle and charter revision.
- Record the actual governed command artifact. Never use `echo dispatch ...` as proof that a
  different command was governed.
- Convert Jagg into a governed worker: it accepts signed/bound work orders and returns signed
  receipts. Its local `run.sh` must not be a live bypass.
- Route recipes, specialists, manager tasks, reflexes, and Autoturret through the same executor.

### Containment

Regex command filtering is not a sufficient sandbox. Run the worker as an unprivileged account
inside a constrained process and network boundary:

- exact destination allowlist derived from the active charter and target generation;
- deny all other egress, including arbitrary hostnames and fleet-LAN destinations;
- bounded CPU, memory, process count, output size, wall time, and workspace;
- no inherited secrets, host credentials, Docker socket, GPU devices, or privilege escalation;
- explicit handling for callbacks/listeners within the charter rather than a blanket network
  exception.

The existing destructive-token check remains useful defense in depth, but it cannot be treated
as complete mediation.

### Acceptance tests

- Monkeypatch every ordinary subprocess/process-spawn entrypoint to fail; the complete synthetic
  engagement still works through the injected governed worker only.
- Arbitrary public domains, arbitrary `.htb` names, fleet-LAN addresses, loopback, and unlisted
  IPs are denied unless they are exact charter entries.
- Alternate destructive spellings are contained even if the command parser misses them.
- A stale head, expired capability, changed target generation, wrong objective digest, missing
  approval, exceeded budget, or verifier/executor identity collision fails closed.
- The receipt's command digest matches the command the worker actually executed.
- An allow decision and every denial appear in the witnessed ledger.

## H3 — Make proof, findings, and completion honest

Priority: P0  
Failure addressed: an empty Cartographer can report 100% complete, and a hypothesis can be
confirmed with no evidence.

### Change

- An empty or uninitialized map is `INCOMPLETE` with reason `no_surface_discovered`.
- Every engagement must have a declared scope object. Absence or corruption of scope blocks
  completion.
- Replace the single overloaded node state with independent dimensions where needed:
  discovery coverage, reachability/access, test outcome, and lifecycle closure.
- A confirmed verdict requires at least one evidence reference resolving to a verified governed
  receipt for the same battle, target generation, node, hypothesis, and bounded objective.
- Reject unknown, stale, duplicate, unverified, or cross-target evidence references.
- Plain `FINDING <text>` may create an operator note, but never a confirmed vulnerability.
- Separate two terminal states:
  - `assessment_complete`: required scope enumerated, hypotheses resolved, evidence verified,
    cleanup from test execution discharged or explicitly transferred.
  - `closure_complete`: remediation disposition recorded and every required retest resolved.
- `DONE` requires `assessment_complete`. `DONE FORCE` records an incomplete forced stop and can
  never render as complete.

### Acceptance tests

- Blank map, missing scope, zero discovered hosts, untouched surface, open hypothesis, pending
  cleanup, and unverified evidence each block completion with a stable reason code.
- Confirming with an empty evidence list raises a typed error and creates no finding.
- A verified receipt bound to another target generation cannot confirm the current hypothesis.
- Retest results cannot be recorded without identifying the finding, remediation disposition,
  tester, timestamp, and evidence receipt.
- Report totals and completion statements are derived from the same authoritative object used by
  the manager's `DONE` gate.

## H4 — Establish one source of truth and reproducible deployment

Priority: P1  
Failure addressed: Kaloth Gunbelt, the `/mnt/sata` governed core, and Jagg contain divergent and
partly unversioned implementations.

### Change

- Keep one version-controlled source tree and produce role-specific release artifacts from it.
- Treat Jagg as a deployed worker, not an independent hand-edited source tree.
- Add `deploy/manifest.json` containing release ID, Git revision, schema versions, allowed files,
  SHA-256 digests, machine role, endpoints, and minimum compatible peer versions.
- Make deployment atomic: stage, verify hashes and offline smoke tests, switch a versioned
  symlink, then retain the previous release for rollback.
- Preflight must verify Lenz, governed core, Ariadne, manager schema, Jagg worker identity,
  release compatibility, and that all direct-execution entrypoints are disabled.
- Classify generated run state, backups, datasets, and secrets explicitly in `.gitignore` and the
  deployment manifest. Eliminate ambiguous untracked source.
- Update README, CHECKPOINT, SIGIL, and the architecture atlas from the same release decision.

### Acceptance tests

- Kaloth and Jagg report the same release ID and the expected role-specific hashes.
- A changed executable, missing manifest, incompatible schema, or unavailable required service
  prevents arming.
- Jagg does not require an undeclared local service. Its Ariadne and model endpoints are explicit
  and health-checked according to the manifest.
- A clean checkout can reproduce the offline test result and deployment package.

## H5 — Add the missing end-to-end contract suite

Priority: P1  
Failure addressed: strong unit tests exist in the governed core, but the boundaries between the
manager, trooper, executor, verifier, Cartographer, report, Lenz, and Jagg are largely untested.

### Required synthetic scenario

Build one target-free fixture that exercises:

```text
manager objective
  -> trooper command proposal
  -> policy allow or deny
  -> contained worker receipt
  -> dirty artifact hash
  -> independent verification
  -> sanitized observation
  -> Cartographer transition
  -> hypothesis verdict
  -> finding package
  -> report
  -> cleanup
  -> remediation disposition
  -> retest
  -> assessment/closure completion
  -> signed Lenz projection
```

### Assertions

- The manager and Codex never receive the command, raw output, secret value, artifact path,
  target identifier, or finding prose through their restricted views.
- A false trooper narrative cannot create evidence or advance the map.
- A correct hash with the wrong semantic binding cannot confirm a finding.
- Every state transition is reproducible from the witnessed event ledger.
- Restart, duplicate request, stale head, partial write, timeout, worker crash, and verifier crash
  preserve fail-closed behavior and idempotency.
- The suite makes no network connection and never imports a live launcher.

Also repair the eight currently failing BS2 UI tests before declaring the release green.

## Implementation order

1. H0: close alternate observation paths.
2. H1: freeze the manager/trooper contract.
3. H2: make the governed worker the exclusive execution path.
4. H3: repair evidence and completion invariants.
5. H5: prove the whole chain with synthetic fixtures.
6. H4: package and deploy the proven release to Kaloth and Jagg.
7. Perform a human-reviewed local-lab canary.
8. Re-enable live engagements only after the canary ledger, Lenz projection, report, and cleanup
   all verify.

## Release gate

The hotfix release is acceptable only when all of the following are true:

- no production command can execute outside the governed worker;
- no capability exists without a witnessed human approval;
- no Codex-visible run observation exists outside Lenz;
- no finding can be confirmed without independently verified evidence;
- no empty, unknown, or incomplete engagement can report complete;
- the complete offline contract suite is green;
- the ordinary BS2 suite and UI tests are green;
- Kaloth and Jagg pass the same signed release preflight;
- a human-reviewed local-lab canary passes without target or scope leakage.

Until then, BS2 should be described as a development system with live execution disabled—not as
a fully governed autonomous pentest platform.
