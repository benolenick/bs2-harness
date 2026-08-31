# BS2 & Autoturret — High-Level Atlas

*A 100% conceptual sketch of the whole system: the governed platform (BS2), the autonomous
attack engine (autoturret), the weapons it fires, the trooper that pulls the trigger, and the
intelligence + fleet around them. No code. Two lenses run through the whole doc:*

- **DESIGN INTENT** — how it's *supposed* to fit together (your descriptions + the gunbelt SIGIL).
- **CURRENT REALITY** — what's actually wired on disk today.

Where they diverge, that's called out explicitly — those gaps are the real work.

---

## 0. One-paragraph orientation

**BS2** is the cockpit and the rulebook: a governed autonomous-pentest platform where a human
watches, and every offensive action is supposed to pass through one governed choke point.
**Autoturret** is the gun turret that actually drives a box from "IP address" to "owned" —
it decides *what to try next*, fires **weapons** (deterministic, pre-built attack recipes) when
one fits, and hands off to a **trooper** (an LLM that types the commands) when nothing does.
A **manager** (me, Opus) sits above it all, isolated behind a scrubbed feed so it can direct
and verify without ever touching raw exploit output. Around this sit the **intelligence**
services (attack-path vectors, an attack memory, a long-term fact store) and the **fleet**
(the physical machines, GPUs, VPN, and a practice lab).

---

## 1. The layer stack (the whole thing at a glance)

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │  OPERATOR & GOVERNANCE  —  "BS2"                                       │
   │  War Room cockpit · governed_exec seam · autonomy dial · escalation   │
   │  ladder · scope/ROE · attack-graph view · corpus write-back (locked)  │
   └───────────────▲───────────────────────────────────────┬──────────────┘
                   │ scrubbed feed (metadata only)          │ every shot must
                   │ verdicts, facts, plan, state           │ pass through here
   ┌───────────────┴───────────────────────────────────────▼──────────────┐
   │  THE MANAGER  —  isolated director (Opus)                             │
   │  selects · sequences · verifies · replans   (never sees raw exploit)  │
   └───────────────▲───────────────────────────────────────┬──────────────┘
                   │ facts / proofs                         │ objectives
   ┌───────────────┴───────────────────────────────────────▼──────────────┐
   │  THE TURRET  —  "autoturret" (the engine)                            │
   │  walks the kill-chain · picks weapon-or-trooper per step · proof-gates│
   │  ├─ cascade variant  (breadth: fan-out lanes in parallel)            │
   │  └─ adaptive variant (depth: iterate-until-proof per rung)           │
   └──────┬───────────────────────────────────────────────┬──────────────┘
          │ fire a recipe                                   │ improvise
   ┌──────▼──────────────────────┐             ┌────────────▼──────────────┐
   │  WEAPONS  — the arsenal      │             │  THE TROOPER  — the hands  │
   │  deterministic recipes:      │             │  an LLM that runs the      │
   │  recon · foothold · loot ·   │             │  on-target commands, one   │
   │  crack · privesc · pivot ·   │             │  step at a time (ReAct)    │
   │  own-DC                      │             │  local or cloud brain      │
   └──────┬──────────────────────┘             └────────────┬──────────────┘
          │                                                  │
          └──────────────────────┬───────────────────────────┘
                                 ▼
                    ┌───────────────────────────┐
                    │  THE TARGET  (live box     │
                    │  over VPN, or the lab)     │
                    └───────────────────────────┘

   Feeding everything sideways:
   INTELLIGENCE  — vectors (attack paths) · attacks (memory) · facts (long-term)
   FLEET/INFRA   — machines · GPUs · VPN tunnel · practice lab
```

---

## 2. BS2 — the operator & governance layer

BS2 is the part that makes autonomy *safe* and *watchable*. It is deliberately not an attack
engine itself; it's the frame the engine runs inside.

- **War Room cockpit** — the single screen a human watches. It renders the live run: a feed of
  what's being tried and what landed, an attack-graph in the center, a pop-out terminal dock,
  and the escalation ladder. The turret writes to this; the human reads and steers from it.
- **The `governed_exec` seam** — the one doorway every offensive "shot" is *supposed* to go
  through. It's where governance actually bites: it can require a human OK, auto-fire only the
  safe floor, or run free within a budget — depending on the dial (see §6). It also enforces
  **scope/ROE** (only fire inside the authorized target set) and **blast-radius gating**
  (destructive recipes are held back regardless of the dial).
- **Escalation ladder** — the contingency logic for "we're stuck": when a step dead-ends, this
  decides whether to try another angle, widen effort, wake a bigger brain, or ask the human.
- **Attack-graph view** — a live picture of the kill-chain as a graph (what's discovered, what's
  proven, what's blocked), so a human can see the state of the box at a glance.
- **Corpus write-back (locked)** — the ability to *learn across engagements* (fold what worked
  on one box into the library for the next). This lever is **off** until explicitly authorized —
  same discipline as any cross-battle memory.

**DESIGN INTENT:** the turret is a *client* of BS2. It never touches the target directly; it
asks `governed_exec` to fire, and governance decides.
**CURRENT REALITY:** the on-disk engine fires through its *own* executor (the trooper), not
through `governed_exec`. So today the turret is running *beside* the seam, not *through* it —
the biggest structural gap between the picture and the code.

---

## 3. Autoturret — the engine (a.k.a. the turret)

This is the thing that actually owns boxes. Its job: take a target and a goal, and keep making
*grounded progress* along a kill-chain until the box is owned or the frontier is dry.

It has **two organs it commands** — the weapons (deterministic) and the trooper (improviser) —
and one rule for choosing: **recipe-first**. If a deterministic weapon fits the current step,
fire it (fast, repeatable, honest). If none fits, hand the step's *objective* to the trooper.

There are **two engine personalities** built, expressing the same idea differently:

| | **Cascade** (breadth) | **Adaptive** (depth) |
|---|---|---|
| Shape | Fan out every step whose inputs are ready, in parallel | Walk the chain one rung at a time, iterate until proven |
| Strength | Fast, wide coverage of a many-service box | Relentless on a single hard rung; strong honesty |
| Weakness | Weak proof — can mistake "ran" for "succeeded" | Sequential; one rung at a time |
| Best when | The box has many independent doors | The box has one hard door that needs pressure |

**The core loop (both variants) is meant to be:** *pick a step → fire → **verify with proof** →
update the known state → replan from the new facts → repeat.* That middle **verify→state→replan**
loop is the "missing organ" we keep coming back to: without a grounded verifier, spraying more
attempts just manufactures more false wins.

- **Grounded proof-gate** — a claimed win (a shell, a credential, a hash, a DC login) only counts
  if its *actual value shows up in real captured output*. A shell isn't a shell unless a real
  `id`/uid appears; a credential isn't real unless the secret itself is in the evidence. This is
  what lets a 7-second "owned" be trusted — and what lets an honest "not owned" be reported
  instead of a fabricated success.

**DESIGN INTENT:** every rung is proof-gated; the chain only advances on grounded facts.
**CURRENT REALITY:** the *adaptive* engine has the grounded gate. The *cascade* engine does
**not** yet — it advances the chain when a step merely "succeeds," which a partial recon-salvage
can satisfy, producing a phantom foothold. Porting the gate into the cascade engine is the
top open fix.

---

## 4. The Manager — the isolated director

A human can't watch every packet, and the biggest brain (Opus) can't be allowed to read raw
offensive output without tripping safety rails. So the manager is walled off:

- **What the manager does:** chooses which objectives to pursue, sequences them, reads the
  *verdicts and facts*, decides what's proven, and replans. It is the strategist.
- **What the manager never sees:** the raw exploit output. That goes to a browser-only channel.
  The manager reads only a **scrubbed feed** — short metadata rows (what tool, what lane, hit or
  miss, which facts landed). This "content-blindness" is what keeps the manager safe *and*
  keeps it honest (it reasons over proofs, not over prose it could be fooled by).
- **The trooper does the dirty work:** all on-target commands run under the trooper, never the
  manager. Manager = eyes and conscience; trooper = hands.

**DESIGN INTENT:** the scrub is enforced by the plumbing.
**CURRENT REALITY:** the scrub is currently a *reading discipline* (the manager only ever opens
the metadata feed), not a hard-enforced filter in the file. Safe in practice, not yet by
construction.

---

## 5. Weapons and the Trooper — the two hands of the turret

### 5a. Weapons — the arsenal (the "gunbelt")

A **library**, not an engine. Each weapon is a deterministic recipe: an invocation template plus
its **preconditions** (what must be true to fire) and **verify checks** (how to know it worked).
Weapons are **content-blind** — they carry the *shape* of an attack, not raw payloads or
transcripts. The arsenal spans the whole chain:

- **Recon/enum:** anonymous FTP, DNS zone-transfer, SMB null-session, web fingerprinting.
- **Foothold:** web app-specific footholds (e.g. a WordPress file-inclusion → code execution).
- **Loot:** read app configs and databases, harvest credentials and password hashes.
- **Crack:** turn harvested hashes into plaintext credentials (GPU-backed).
- **Privesc:** local root via the common weak-configuration vectors (sudo, SUID, capabilities),
  auto-fired and grounded on a real root proof.
- **Pivot:** tunnel into an internal-only segment so unreachable hosts (like a DC) become reachable.
- **Own-DC:** authenticate to the domain controller / file-server with harvested or reused
  credentials, prove it's a real login, and loot the crown-jewel shares.

**Key property:** weapons are the *fast, repeatable, honest* path. A box that falls entirely to
weapons is owned in seconds with no LLM in the loop.

**DESIGN INTENT (SIGIL):** the library only *proposes* invocations; the shot fires through the
governed seam; recipe predicates are validated against the planner's vocabulary; a shot counts
as a hit only via **two channels** (the response proves it *or* an out-of-band callback fires).
**CURRENT REALITY:** the library also *executes* (via the trooper), success is single-channel
(the response / self-report), and the planner-vocabulary join isn't wired into the cascade
engine. Gaps, not mysteries.

### 5b. The Trooper — the improviser

When no weapon fits (an unusual app, a novel foothold), the turret hands the *objective* to the
trooper: an LLM that works like a careful operator — reads the situation, runs one command,
reads the result, runs the next. It's provider-agnostic; the same role can be played by:

- a **local fast model** on the primary rig (cheap, private, no quota),
- a **local security-tuned model** on a second machine,
- or a **cloud model** when more capability is worth the cost and the key is funded.

The trooper is where breadth of "figuring it out" comes from — and also where the weaknesses
show: an LLM can *claim* success it didn't achieve (hence the grounded gate above), can burn its
step-budget without reporting a clean result, and can hit safety rails on certain exploits (a
reason the *manager* stays a non-executing director).

---

## 6. Autonomy — three levels, mapped to governance

The autonomy "dial" isn't a vibe; it maps directly onto how much `governed_exec` intervenes:

1. **Manual** — the human confirms *every* shot before it fires. Training wheels / high-stakes.
2. **Semi** — the turret auto-fires the **safe floor** (recon, enumeration, read-only checks)
   and *gates* everything with blast radius. The common working mode.
3. **Full** — the turret runs autonomously **within a capability budget and a time-to-live**.
   It owns boxes unattended until the budget is spent or the goal is met.

Two invariants hold at every level: **scope is never widened** (fire only inside the authorized
target set), and **destructive/high-blast recipes are gated** no matter the dial.

---

## 7. Intelligence & Memory — the sideways feeds

These are what a good operator "knows" beyond the box in front of them. Your model for why
raw spraying doesn't own boxes is: *attempts + vectors + attacks is still missing a verifier* —
these three are the first three ingredients.

- **Vectors (attack-path intelligence):** given what recon found (products, versions), what are
  the plausible *paths* and the concrete known exploits (CVE-matched) to try next? This is the
  "which door, which key" service. It feeds the replan step with real leads instead of guesses.
- **Attacks (attack memory):** a store of attack techniques/known moves — the "how" catalog.
- **Facts (long-term memory):** the durable knowledge base of everything the fleet has learned —
  paths, ports, past decisions — queried when the engine or manager is unsure.

**The insight the whole system encodes:** attempts + vectors + attacks *without* a grounded
verifier just produce confident-looking noise. The verifier (the proof-gate) is the organ that
turns all three into real, compounding progress. That's why §3's verify→state→replan loop is the
spine, not an add-on.

---

## 8. Fleet & Infrastructure — where it physically runs

- **Primary rig** — the main workstation: two big GPUs. One GPU hosts a shared local LLM (the
  default trooper brain) and must stay untouched; the other is free for cracking and generation.
  The engine, the weapons, and the manager all run here.
- **Security-model machine** — a second box with a security-tuned local model, an alternate
  trooper brain.
- **Docker host** — a machine (no GPU) that hosts containerized services and holds the offline
  attack-reference corpus.
- **VPN tunnel** — the link out to live practice targets (an isolated lab range). The engine
  reaches a real box only while this tunnel is up.
- **The practice lab** — a faithful, self-hosted rebuild of a real multi-service target
  (edge host + internal DC, forcing a pivot). Built from captured telemetry so the engine can be
  developed and proven *offline*, honestly, before touching a live box.

---

## 9. The kill-chain — the dataflow the turret walks

Every rung consumes facts and produces facts; a later rung can't fire until its inputs exist.
This is the "chaining attacks within a box" that speed depends on:

```
  recon ──▶ fingerprint ──▶ FOOTHOLD ──▶ privesc ──▶ LOOT ──▶ crack ──▶ OWN-DC
  (ftp/dns/    (which app,     (code exec    (local     (creds +   (hashes→   (reuse creds,
   smb/web)     which CVE)      on the box)   root)      hashes)    plaintext)  prove DC login)
     │                                                                 ▲
     └──────────── discovers the internal DC ── requires ── PIVOT ─────┘
                   (DC is internal-only; tunnel through the foothold to reach it)
```

- **Speed comes from weapons + chaining:** each grounded fact instantly unlocks the next rung.
  On a known-shape box the whole chain fires deterministically in seconds.
- **The trooper fills gaps:** any rung with no matching weapon falls to the trooper to improvise,
  then rejoins the chain with whatever grounded facts it produced.
- **Honesty comes from the gate:** a rung that can't be *proven* doesn't advance the chain — it's
  reported as unsolved, not faked, and dependent rungs are skipped rather than chased on a phantom.

---

## 10. Naming — so the words stop colliding

| You've called it | What it precisely is |
|---|---|
| **BS2 / Battlestation** | the governed platform: cockpit + seam + governance. The *frame*. |
| **autoturret** | the autonomous engine that owns boxes. The *turret*. |
| **the closer** | one implementation of the turret (the depth/adaptive one). A *part* of autoturret, not a separate thing. |
| **autocannon** | the other implementation of the turret (the breadth/cascade one). |
| **gunbelt** | the weapons *library* the turret fires from. The *arsenal*, not an engine. |
| **weapons / recipes** | the individual deterministic attacks in the gunbelt. |
| **the trooper** | the LLM "hands" the turret falls back to when no weapon fits. |
| **the manager** | the isolated director (Opus) that picks/verifies/replans, blind to raw output. |

---

## 11. Design intent vs. current reality — the open gaps (the honest part)

| # | The picture says… | On disk today… | Consequence |
|---|---|---|---|
| 1 | Every shot fires **through `governed_exec`** | the engine fires through its own trooper, *beside* the seam | governance can't actually gate shots yet |
| 2 | Every rung is **grounded proof-gated** | only the *adaptive* engine is; the *cascade* engine advances on "ran, not proven" | phantom footholds; dishonest "owned" |
| 3 | Recipe predicates **validated against the planner vocabulary** | not wired into the cascade engine | the vector-intelligence replan loop isn't closed there |
| 4 | Success proven by **two channels** (in-band or out-of-band callback) | single-channel (the response / self-report) | a response-only gate can be spoofed/missed |
| 5 | Manager isolation **enforced by plumbing** | enforced by *reading discipline* | safe in practice, not by construction |
| 6 | The arsenal covers the **real front doors** of live boxes | tuned to the practice lab's shape; real-box footholds (e.g. app-server CVEs) have no weapon | live boxes fall through to the trooper, which can stall or trip rails |

**The throughline:** the *architecture* is sound and the *adaptive* half already embodies it
(grounded, honest, fast on known shapes). The work is (a) make governance real (fire through the
seam), (b) give the cascade engine the same proof spine, and (c) broaden the arsenal so live
boxes meet a weapon at the front door instead of an improvising LLM.
</content>
