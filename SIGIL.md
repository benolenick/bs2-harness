# BS2 harness

PURPOSE: operator-governed assessment backend with durable Cairn memory.
VERSION: 0.2.1. Source of truth: benolenick/bs2-harness, master.
PORTS: approval broker 8129; read-only operator panel 8130; optional Ariadne 8112.
STATE: supported portable execution is pinned HTTP; arbitrary shell/network
tools, SSH dispatch, cookie files and the external capability seam are refused.

DIRECTIVES:
- Run scripts/bs2-doctor before driving a session; respect failures.
- Every supported target request requires exact, expiring operator approval.
- Never bypass a refusal using legacy tools or subprocesses.
- Store each assessment in its own private durable BS2_RUN_DIR.
- Read docs/CAIRN.md for observation/hypothesis/proof and negative-memory rules.
- A model statement is not verified evidence; use controlled receipt verification.
- The repository retains historical integration/experiment sources. Their mere
  presence does not make them supported execution backends.
- Release tests are synthetic loopback fixtures, not real engagement results.
