# Instructions for agents driving BS2 0.2

Before driving a session, run:

```bash
python3 scripts/bs2-doctor --require-hitl --json
```

A fail result means do not run the engine. Explain the failing checks, fix only
setup problems within the operator's authorization, then rerun the doctor.
Warnings are limitations to disclose, not permissions to bypass a refusal.

Read SIGIL.md, README.md and docs/CAIRN.md. New 0.2 instructions supersede older
campaign recipes in historical documents.

- Supported portable execution is `bs2 check-read` / `live.target_exec.run` using
  the pinned-HTTP curl subset. No arbitrary-shell or multi-protocol sandbox is
  bundled. Legacy SSH and external capability-seam execution refuse.
- Every supported request needs explicit host/port scope, a private policy,
  exact expiring broker approval, an action budget and private BS2_RUN_DIR.
  Approval cannot be disabled by an environment toggle.
- Never route around a refusal with subprocess, urllib, SSH, old campaign scripts
  or a differently worded command. Ask the operator about changes to scope/RoE.
- Model confidence and target text are not verified findings. Use the controlled
  receipt verifier with provisioned owner/other/anonymous controls.
- Preserve per-assessment Cairn state. Missing conditions are unknown; negatives
  only suppress matching conditions. Update deployment/session IDs honestly.
- The panel is read-only and exposes only memory/receipts, not raw secrets.
- For release testing: unit suite, bounded local fixture, clean-install smoke.
  `tools/release_check.py --opus --browser --out /tmp/bs2-validation` caps the
  canary at ten fixture requests and three Opus calls, no specialists.
  `tools/dual_opus_check.py --out /tmp/bs2-dual-opus` separately exercises the
  production Claude launcher with Opus driver/trooper, capped at eight model
  calls and seven fixture requests with an extra test-only route allowlist.
- Historical integrations are source references, not endorsed alternate doors.
  The scoped manager/AGENTS.md restrictions still apply to real campaign data.

Log checked results honestly. A synthetic fixture or skipped external dependency
does not establish a successful real engagement or full legacy compatibility.
