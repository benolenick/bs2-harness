# Autoturret — NORTH STAR

*The single durable statement of what this engine is for. Every design decision serves this.
Set by Ben 2026-08-22. Do not dilute it; when a change doesn't serve this, it's the wrong change.*

## The one sentence

> A pentest engine that throws **intelligently** — so much (grounded) attack surface at a box
> that when one or many things stick, they **all get instant follow-up, and follow-up**, until
> the box is owned or it is **genuinely out of ideas** (minutes, not hours) — and then the most
> successful streams become **extremely valuable recon** for the trooper and the manager.

## The five properties that sentence demands (each maps to one organ)

1. **Intelligent throwing, not brute spray.** The shortlist of what to try next is chosen from
   *proven facts* by **Ariadne** (`/recon` for next leads, `/exploits` for CVE-matched shots).
   The corpus (58G RAG on your-host) *arms* each shot with a concrete invocation. Brute enumeration
   is the floor, not the strategy.

2. **Parallel stick-detection.** Every lane whose preconditions are met fires concurrently
   (breadth fan-out, inherited from autocannon). Many things stick at once — that's wanted.

3. **Instant follow-up (event-driven, NOT round-barrier).** The moment ONE lane lands a grounded
   fact, its dependent lanes are computed and fired immediately — no waiting for a round to drain.
   The scheduler is a rolling `as_completed` loop over one long-lived pool, re-planning on every
   completion. This is THE behavioral change from the old autocannon.

4. **Grounded, or it doesn't count.** A fact advances the chain only if its value is BACKED by
   real captured output (a `shell=` needs a real `uid=`; a `cred=` secret must literally appear).
   Self-reported LLM facts are rejected. Without this, instant follow-up just fans out on false
   wins faster. "Out of ideas" is a *computed empty frontier* (Ariadne negatives hard-prune),
   not a timeout — plus a TTL so it always terminates in minutes.

5. **Winning streams become recon.** The surviving grounded fact-chain (with provenance: which
   lane proved each fact) is the highest-signal context, handed up to the manager (scrubbed) and
   forward to the trooper. The only thing the system trusts is what it proved.

## The unlock ORDER (do not reorder — each depends on the prior)

1. **Grounded gate** (1.7b/14b verifier + needs-enforcement) — must exist first, or #2 is dangerous.
2. **Event-driven scheduler** — the instant-follow-up behavior.
3. **Ariadne re-plan join** — intelligent throwing (validated predicate vocab; fragile, never blocks).

## Model roles (by task shape — do not misassign)

- **small verifier (14b @ :8000, 1.7b-slottable)** — extract facts + GROUND them, per lane, always-on.
- **14b trooper (:8000)** — improvise where no recipe fits; escalated grounding checks.
- **Ariadne (:8112, no LLM, <200ms)** — re-plan: which leads next / which CVE exploits.
- **Opus manager** — strategy, blind to raw output, reads only the grounded graph.

## Governance

Autoturret is a CLIENT of BS2. Every shot is meant to fire through `governed_exec`; scope/ROE and
blast-radius gating are BS2's, never widened by the engine. The autonomy dial (manual/semi/full)
maps onto how much governed_exec intervenes.

## Honest gaps this north star is measured against (2026-08-22)

- Grounded gate lives in closer.py; must be shared into the breadth engine (this build).
- Scheduler is still round-barrier in autocannon.py (this build replaces it).
- Ariadne `/exploits` is wired (closer); `/recon` re-plan join is not yet closed.
- Real-box front doors (GitLab, etc.) still lack recipes → fall to the stalling trooper.
- The proof gate must reject the `.205` fabrication case (`cred=root:...` with no output) — regression-test it.

---

## THE PLANNER LOOP — the organ that turns a static belt into terrain-driven attack (theorycraft, 2026-08-22)

*This is the #1 unbuilt upgrade. Worked out with Ben. It is NOT a pre-made chain — it composes
the chain live from a manager-set goal + grounded facts. "You catalog terrain-gated attempts;
you never catalog the route between them — the route is planned at runtime."*

**The loop (what autocannon SHOULD do after the floor):**
1. **Floor blasts all universal low-hanging fruit** (anon FTP, zone transfer, null session, web
   fingerprint, default creds, version-matched CVE probes) → grounded facts. This is the general,
   un-overfittable core: it tests *categories* of misconfig, not this box. The trooper never
   wastes turns on the easy stuff.
2. **Whatever ADVANCES** (the grounded facts) is handed up.
3. **The manager sets the immediate ATTAINABLE goal** — not "own the DC," the next concrete rung
   (`rce_as(webhost)`, then `read_file(flag)`, then `pwn_host`). Manager's only job here: pick the
   goal. It never runs the attack.
4. **Ariadne `/plan` returns a PATH** of technique-operators from the facts we HAVE to that goal.
   Grounded path (assumptions=[]) = real; relaxed path lists assumptions = recon tasks.
5. **Fire automated attempts along the path.** Each operator maps to a WEAPON (recipe) if we have
   one for it, else the TROOPER improvises that single step, armed by Ariadne `/exploits` + corpus.
6. **Prune + re-plan.** A step that FAILS is fed back to Ariadne as a NEGATIVE, which HARD-PRUNES
   that whole branch; Ariadne returns a DIFFERENT path. Loop until the goal is grounded, or every
   branch is pruned = **genuinely out of ideas** (computed, not a timeout). Relaxed-only? use
   `/recon` to rank the cheapest observable to confirm next, confirm it, add as fact, re-plan.

**Why this is the answer to the overfitting worry:** the thing that generalizes is the LOOP
(discover → plan → fire → ground → prune), not a recipe library. A recipe is a cached, hardened
instance of one operator. Measure success by "can it own a box using an operator we never wrote a
recipe for" (general), NOT by recipe coverage (overfit). Develop on some boxes; EVALUATE on
held-out boxes never tuned against.

**The vocab-join is the keystone (SIGIL-flagged):** Ariadne HARD-REJECTS any out-of-vocab
predicate. Our floor facts must be translated into Ariadne's exact predicates before /plan works:
  - `app=<prod>:<host>`  -> `vuln_present(<host>,<prod>)`   (+ `reachable`)
  - Ariadne `/exploits?q=<prod>` match -> `known_exploit(<prod>, EDB-<id>)`  (version-matched=grounded)
  - `shell=<user>` -> `rce_as(<user>)` + `runs_as(<endpoint>,<user>)`
  - `cred=<u>:<p>` -> `have_cred` (+ `cred_reused_on` if reused)   ·   `hash=` -> `crackable_hash`
**Keystone operator** `run-public-exploit`: `vuln_present + known_exploit + runs_as -> rce_as`.
Then `os-rce-file-read` (`rce_as + can_read -> read_file`) and GTFOBins ops (`-> rce_as(root)`).

Implementation: `live/autoturret_planner.py` (translate/plan/recon/map) wired into
`autoturret.py --planner`. Belt stays as the FLOOR; the planner drives the tail.
