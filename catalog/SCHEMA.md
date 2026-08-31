# gunbelt recipe schema

A recipe is one firable invocation. The catalog is a list of these. The agent (or the
auto-fire runtime) selects recipes whose `when` preconditions are satisfied by current
facts, then fires them at the chosen autonomy level.

```yaml
- id: <stable-kebab-id>            # e.g. smb-null-session
  name: <human label>
  phase: recon|enum|exploit|cred|privesc|lateral|loot|persist
  tier: floor|standard|heavy       # floor = cannot be skipped; heavy = always gated
  autonomy: manual|semi|full       # the LOWEST dial at which this may auto-fire
  when:                            # preconditions — matched against battle facts
    - service: smb                 # facet the recipe needs to be true
    - port: 445
  tool: <binary>                   # the gun (must exist in sandbox toolset)
  invocation: >                    # parameterized template; {{host}} {{port}} {{userlist}} etc
    nxc smb {{host}} -u '' -p '' --shares
  parallel_safe: true|false        # may fire concurrently in a volley?
  blast_radius: none|low|high      # high => gated regardless of dial
  verify:                          # how we know it worked (drives write-back + facts)
    success_if: <regex or predicate over stdout/exit>
    emits: [<fact templates it produces on success>]   # e.g. cred, share, host-owned
  cost_hint: cheap|moderate|slow   # scheduling hint (phpass crack = slow, etc.)
  notes: <one line; opsec/gotchas>
```

## Selection contract
1. Filter catalog to recipes whose `when` is satisfied by current facts.
2. Drop any whose `blast_radius: high` unless the dial + a live capability authorize it.
3. FLOOR-tier recipes are force-included whenever their `when` holds (un-skippable).
4. Group `parallel_safe: true` into a volley; fire serially otherwise.
5. On success, `verify.emits` become candidate facts fed back to the planner (BS2 L1b).
6. If write-back is ON, a recipe that verified success is promoted to the corpus (BS2 L3).

## What a recipe is NOT
Not an exploit payload, not a transcript, not a stored flag/loot value. Templates and
preconditions only — content-blindness holds.
