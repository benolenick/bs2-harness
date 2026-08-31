# The two-agent experiment: specialist × generalist on a shared seam
**Date:** 2026-08-24  ·  **Task:** un-starve Ariadne (the attack-path planner the manager was ignoring)
**Agents:** `om-b5` (system generalist, whole-BS2 view) × `om-00` (Ariadne specialist, deep-narrow view)
**Verdict up front:** it worked, and it worked *because* we split at a data contract, not at the code.

---

## The setup

Ben's hypothesis, tested live: **one specialist agent with a fresh, narrow view + one generalist
agent with the whole-system view will cover a problem that neither could cover alone** — if you give
them the right seam to meet at.

- **om-00 (specialist):** saw *only* Ariadne. Deep on the planner internals — predicates, operators,
  the /plan and /recon endpoints, the confirmed-negatives prune. Blind (by design) to BS2's ROE,
  the trooper roster, the UI, the manager bridge.
- **om-b5 (generalist):** saw the whole system — BS2, the ROE/posture kernel, the 41-trooper roster,
  the manager bridge, autoturret's fire loop, the UI. Shallow on Ariadne's guts.

Same task, opposite-shaped knowledge.

## The coordination primitive: lock one contract, then work in parallel

The thing that made it work: **we locked the advisory contract early** (gunbelt-17) and *both* agents
coded against it independently. Neither waited on the other's code.

    advisory = {
      stamp{facts_n, corpus_hash, ts},                 # om-00 owns
      goals[{goal, status, assumptions, path, ...}],   # om-00 owns
      recon_next[{confirm, unblocks_goal, gain}],      # om-00 owns  (ranked by GAIN, not time)
      troopers[{id, goal, score, gate, bespoke}]       # om-b5 owns  (goal->trooper join + posture gate)
    }

om-00 filled the left half from the Ariadne side (posture-BLIND — it doesn't know or care about ROE).
om-b5 filled `troopers[]` and layered the posture/ROE gate on top. They **merge in `build_advisory`**.
That single shared shape is why two agents never collided.

## What each caught that the other structurally could not

This is the actual payoff — each view caught errors invisible from the other seat.

**Specialist caught the generalist's mistakes (planner semantics):**
- I keyed goals on the raw predicate `session`. om-00: *"`foothold` ≠ `session` — the ladder is 6 rung
  LABELS, and foothold maps to exploit troopers, rce_as maps to privesc."* I'd have built a false rung.
- I ranked `recon_next` by `cost_ms`. om-00: *"Ariadne has no time model — rank by `gain`."* Correct;
  the planner literally cannot estimate wall-clock, so a cost sort would have been noise.
- I inferred troopers from surface *tokens*. om-00: *"consume `worklist.json` — it's already
  class-tagged, 70 rows; strictly better than re-inferring from tokens."* It was.

**Generalist caught the system seams the specialist couldn't see:**
- The **merge point itself** — om-00's advisory was half a contract; it needed the `troopers[]` join and
  a place to meet. That's a whole-system fact.
- **Posture / ROE gating** — om-00 built the planner posture-blind (correctly). Someone with the ROE view
  had to add the gate so "broadside vs surgical" actually filters who fires. The specialist couldn't,
  because ROE isn't in the Ariadne worldview.
- **The signal-feed mismatch** — om-00's oracle spoke web-surface facts; the manager's `recon.json` spoke
  app-level fingerprints. The empty `troopers[]` bug was a *seam* bug, visible only from across the seam.

## Friction (the honest part)

- **A vocab mismatch cost a full cycle.** My first join keyed on surface tokens; recon.json didn't emit
  them → `troopers[]` came back empty and I chased an importlib red herring before realizing it was a
  *data-vocabulary* gap, not a code bug. Fix: om-00 pointed me at the class-tagged worklist. Lesson:
  **when the output is empty, suspect the contract's vocabulary before the code.**
- **The join got re-keyed twice** as om-00 improved the upstream feed (tokens → structural facts →
  worklist classes). Each improvement was real, but a moving upstream means the downstream churns.
  Cheap because the *contract shape* held — only the fill source moved.
- **Coordination overhead was real** (numbered mailbox notes + live SendMessage) but smaller than the
  confusion it prevented. The numbered gunbelt-NN thread is a durable, auditable trail — you can read
  exactly who decided what, when.

## What made it work (the transferable pattern)

1. **Split at a versioned data contract, not at the code.** The advisory schema was the whole interface.
2. **Give each agent a genuinely different view** — deep-narrow + wide-shallow. Overlapping views would
   have just produced two of the same agent.
3. **Let the specialist own semantics, the generalist own seams.** Don't let either drift into the
   other's lane — the generalist should *not* try to become the Ariadne expert, and vice versa.
4. **Durable async channel + a live one.** Mailbox for decisions-of-record; SendMessage for "am I
   reading this right?" in the moment.

## Where it landed
- Loop **closed and proven live** on juice-shop: mapper classes → 8 specialists auto-selected
  (sqli 24, nosqli 24, bola 15, authn, jwt, lfi, xss×2), posture gate live (broadside=all fire,
  surgical=0 fire).
- **Nothing merged to the live operator corpus** — all staged, awaiting human bless (DIRECTIVE 1).
- One seam left, and it's not a coordination problem: om-b9's fold apply + a juice respawn = the
  continuous end-to-end "Ariadne drives the manager" demo.
