#!/usr/bin/env python3
"""charter — the human-approved Battle Charter (canonical loop top, 2026-08-25).

The charter is the engagement's constitution: what is authorized, against whom, how,
and what is never allowed. It is DATA (a file the operator signs off), loaded and
enforced by every role below it — hands, trooper, governor, cartographer — instead of
scope rules living only as hardcoded regexes inside the executor.

Default charter = the standing HTB grind engagement (operator's active VPN, spawned
box). Override per engagement with GB_CHARTER=<file>. The charter gates run start
(target mismatch refuses to boot) and renders into the manager's picture, so the
manager reasons INSIDE its terms.

The hard enforcement stays in code (SCOPE_DENY in trooper.py, _DESTRUCTIVE in
target_exec.py) — the charter is the declared source of those rules, not a
replacement for them.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_CHARTER = {
    "title": "HTB grind engagement (standing)",
    "authority": "operator — active HackTheBox VPN, spawned lab target",
    "objective": ("Foothold shell -> loot & crack creds -> pivot to the internal DC -> "
                  "Domain Admin; build the map first, then exploit what you find."),
    "target": "",                    # filled by the run's --target at load time
    "scope": {
        "cidrs": ["198.51.100.10/16", "10.10.11.0/24", "10.10.10.0/24", "172.16.0.0/12"],
        "hosts": [],                 # the engagement target, added at load
        "excluded_cidrs": ["10.10.14.0/24", "10.10.15.0/24", "192.0.2.10/16",
                           "127.0.0.0/8"],
    },
    "actions": {
        "allowed": ["net.recon", "web.recon", "web.exploit"],
        "forbidden": ["impact.*", "exfiltration", "credential-harvesting-at-scale"],
        "approval_required": [],
    },
    "limits": {
        "max_requests_per_minute": 300,
        "destructive_patterns": ["rm -rf /", "mkfs", "dd of=/dev", "shutdown", "reboot",
                                 "fork bomb"],
    },
    "stop_conditions": ["operator stop", "coverage complete", "explicit exhaustion"],
}


def load(path=None):
    """Load the charter; GB_CHARTER file overrides the default. Returns (charter, source)."""
    src = path or os.environ.get("GB_CHARTER", "").strip()
    if src and Path(src).is_file():
        return json.loads(Path(src).read_text()), src
    return json.loads(json.dumps(DEFAULT_CHARTER)), "default"


def bind_target(charter, target):
    """Stamp the engagement target into the charter (idempotent)."""
    charter["target"] = target
    charter["scope"]["hosts"] = [target]
    return charter


def validate_target(charter, target):
    """The run refuses to boot against a target outside the charter."""
    hosts = (charter.get("scope") or {}).get("hosts") or []
    if hosts and target and target not in hosts:
        return False, f"target {target} not in charter scope hosts: {hosts}"
    return True, ""


def render(charter):
    """One compact, content-blind block for the manager's picture."""
    scope = charter.get("scope") or {}
    acts = charter.get("actions") or {}
    return (f"# BATTLE CHARTER (human-approved — you reason and act INSIDE these terms)\n"
            f"- engagement: {charter.get('title', '')} ({charter.get('authority', '')})\n"
            f"- target: {charter.get('target', '')}   in-scope: {', '.join(scope.get('cidrs', []))}\n"
            f"- allowed: {', '.join(acts.get('allowed', []))}   "
            f"forbidden: {', '.join(acts.get('forbidden', []))}\n"
            f"- excluded nets: {', '.join(scope.get('excluded_cidrs', []))}\n"
            f"- stop conditions: {', '.join(charter.get('stop_conditions', []))}")


if __name__ == "__main__":
    c, src = load()
    print(f"charter source: {src}")
    print(render(c))
