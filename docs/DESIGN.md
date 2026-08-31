# gunbelt — design & phases

## Where gunbelt sits in BS2
BS2's briefs describe one broken loop: SENSE -> ASSEMBLE FACTS -> REASON -> GOVERN-DISPATCH
-> ACT -> LEARN. gunbelt is the ACT vocabulary + part of LEARN:
- it turns "the planner returned operator X" into "here is the exact, precondition-checked,
  parallel-safe invocation to fire for X, and here is how we verify it."
- on success it emits facts back (feeds L1b) and, when authorized, writes the winning recipe
  back to the corpus (L3).
It does NOT replace the driving loop (L1) or the governed_exec seam (L2/L4) — it plugs into them.

## Phases
- **Phase 0 (now): shape lock.** Schema + seed catalog + this doc. No runtime. Decide the
  recipe shape is right before scaling the catalog.
- **Phase 1: catalog build.** Grow seed -> a real arsenal, organized by phase/precondition.
  Source invocations from what already works in pentester_prompt + the pentest RAG corpus
  (your-host ragtrieval: SecLists/HackTricks/atomic-red-team) — templates only, content-blind.
- **Phase 2: selector (manual/library mode).** A pure function: facts -> matching recipes,
  ranked, FLOOR force-included. Agent reads the shortlist and picks. Lowest risk, first A/B.
- **Phase 3: auto-fire runtime (semi/full).** Volley grouping of parallel_safe recipes;
  fires THROUGH governed_exec; verify -> emit facts. This is the "spray commands" capability.
- **Phase 4: write-back (L3).** Winning recipes promoted to corpus; retrieved next battle.
  OFF by default; explicit Ben authorization per the lever discipline.

## The A/B plan (honest lift)
Baseline = naked-Opus. Add one wrapper at a time, measure vs baseline on the enterprise lab:
  1. FLOOR only (coverage floor)        -> expect: fewer missed free wins
  2. + PARALLEL volleys                 -> expect: faster time-to-first-foothold
  3. + WRITE-BACK across >=2 battles    -> expect: battle N+1 faster than battle N
Bare catalog with no wrapper is the null hypothesis (~0 lift) — we include it to prove the
point, not to ship it.

## Open questions
- Selector: pure rules, or a small local model ranking the shortlist? (start pure.)
- Recipe provenance/trust: how does a written-back recipe carry its success evidence without
  carrying content? (sha + verify-predicate + battle-id, not stdout.)
- Overlap with Ariadne operators (61): is a gunbelt recipe just the concrete invocation for
  an Ariadne operator? Likely YES — recipe.id should reference the operator it realizes.
- Lockout/opsec budget for blast_radius:high recipes under full-auto.
