# Cairn in BS2 0.2

Yes: this is the existing Cairn library, vendored from Ben's `/home/om/cairn/cairn`
implementation on 2026-09-11. It is not Hyphae, Memoria, Cartographer, or another
memory system. Vendoring keeps a fresh install independent of workstation paths.
The portable default database path and provenance-aware content deduplication are
the two changes to the shared library copy; the fleet/game copy is untouched.

`receipts.sqlite3` is the authoritative execution journal. `cairn.sqlite3` is its
idempotent projection. One private run directory equals one assessment. Context
is assembled before each supported manager turn and every controlled read check;
observations and verification results fold automatically. `bs2 state` and the
panel show the exact last **Cairn slice**, not the entire manager prompt.

The adapter does not use the generic Curator event importer, which historically
promoted every projected item. It assigns types explicitly:

- HTTP observation: verified *observation*, not a vulnerability verdict.
- Model claim, incomplete check, timeout: hypothesis/inconclusive.
- Controlled private read: confirmed, negative, or inconclusive.
- Negative: suppress only the same request, principal credentials, session epoch,
  target generation and private-resource contract. Any difference reopens it.

Five fresh receipts establish a private-resource check: authenticated identity
for both principals, then owner / other / anonymous requests for the same object.
The operator supplies the identity endpoint and intended privacy contract. Exact
body equality is intentionally conservative; dynamic bodies may need a future
application-specific verifier. No stdout marker or model confidence can confirm.

The slice has an approximate token budget and explicit shedding; suppression is
computed from the full journal, not from whichever negative fits the slice.
Proofs older than five minutes cannot create a new verification event. Prior
verified history remains historical evidence and must be rechecked when needed.

The journal stores hashes and allowlisted identity fields, not tokens, response
bodies, or full prompts. Identity fields and operator-authored memory may still
be sensitive. Keep run directories private. Hash chaining detects damaged history;
it is not protection against a malicious process running as the same OS user.

The deterministic restart benchmark measures a small state-retention contract,
not a claim that Cairn outperforms other systems on real engagements.
