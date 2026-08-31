#!/usr/bin/env python3
"""session_vault — the multi-identity session vault (BS2 design doc §2, 2026-08-25).

Multi-principal differential testing is the killer feature for bank web apps: maintain
ISOLATED identities (anonymous / user-a / user-b / privileged / other-tenant / expired /
MFA-complete vs MFA-incomplete) and systematically compare the same request across them.

HARD RULE: the vault holds REFERENCES to secrets (cookie jar paths, token labels), never
the secrets themselves. Values live in files the operator controls; this module only
tracks what exists, for whom, and in what enrollment state. Persistence is mode-600.
"""
from __future__ import annotations
import json, os, re
from pathlib import Path

KINDS = {"anon", "user", "privileged", "tenant", "expired", "mfa_partial", "mfa_complete"}

PRINCIPAL_SPECS = {
    # kind -> (default label, enrollment meaning, differential role)
    "anon":         ("anonymous",  "no session",        "baseline"),
    "user":         ("user-{n}",   "enrolled",          "ownership axis"),
    "privileged":   ("admin-{n}",  "enrolled",          "role axis"),
    "tenant":       ("tenant-{n}", "enrolled",          "tenant axis"),
    "expired":      ("expired-{n}", "expired",          "session axis"),
    "mfa_partial":  ("mfa-half-{n}", "mfa incomplete",  "session axis"),
    "mfa_complete": ("mfa-full-{n}", "mfa complete",    "session axis"),
}


class SessionVault:
    def __init__(self, run_dir=None):
        self.run_dir = Path(run_dir) if run_dir else None
        self.sessions = {}      # sid -> {principal, kind, refs: {...}, enrollment}
        self.counter = 0

    # ---- registration ---------------------------------------------------------
    def register(self, kind, n=1, refs=None):
        """Create `n` isolated identities of a kind. refs = {cookies: <path-ref>, token:
        <label>} — references only, never values. Returns list of principal ids."""
        label_tpl, enrollment, _role = PRINCIPAL_SPECS[kind]
        out = []
        for _ in range(n):
            self.counter += 1
            pid = f"{kind}:{label_tpl.format(n=self.counter)}"
            sid = f"s-{self.counter}"
            self.sessions[sid] = {
                "sid": sid, "principal": pid, "kind": kind,
                "refs": dict(refs or {}), "enrollment": enrollment,
            }
            out.append(pid)
        return out

    def pair(self, base_kind="user", refs=None):
        """The two-account minimum for ownership testing: user-a + user-b."""
        return self.register(base_kind, 2, refs)

    # ---- queries --------------------------------------------------------------
    def session_for(self, principal):
        """The active session for a principal, or None (anonymous = no session)."""
        for s in self.sessions.values():
            if s["principal"] == principal:
                return s
        return None

    def sessions_for_kind(self, kind):
        return [s for s in self.sessions.values() if s["kind"] == kind]

    def all_principals(self):
        return sorted({s["principal"] for s in self.sessions.values()})

    def matrix_axes(self):
        """The systematic comparison axes from §2, as concrete (label, principals) rows:
        same endpoint × different principal, own vs foreign object, browser vs API, etc."""
        return [
            ("principal", self.all_principals()),
        ]

    # ---- persistence (mode 600) ------------------------------------------------
    def save(self):
        if not self.run_dir:
            return
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / "session_vault.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"sessions": self.sessions, "counter": self.counter}, indent=1))
        os.replace(tmp, path)
        try: os.chmod(path, 0o600)
        except Exception: pass

    @classmethod
    def load(cls, run_dir):
        v = cls(run_dir)
        path = Path(run_dir) / "session_vault.json"
        if path.exists():
            d = json.loads(path.read_text())
            v.sessions = d.get("sessions", {})
            v.counter = int(d.get("counter", 0))
        return v


__all__ = ["SessionVault", "KINDS"]
