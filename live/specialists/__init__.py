#!/usr/bin/env python3
"""specialists — typed experiment contracts + event-driven wake/sleep (BS2 doc §3-§4).

A specialist is NOT a Markdown prompt. It is a typed contract:

  triggers      — map facts that make it relevant
  requires      — preconditions that must ALL hold before it wakes
  adapters      — the shared platform pieces it may use (differential / workflow)
  budgets       — max_requests / max_tokens / max_minutes
  mutation      — read_only unless the operator grants otherwise
  oracles       — the success predicates its deltas are judged against
  terminal      — confirmed | rejected | inconclusive | blocked | not_applicable
  wake_again_on — map events that re-activate it after it sleeps

Its OUTPUT is a proposed experiment (endpoint/principal/object-binding/oracle/ceiling),
executed by the shared replay engine — never a shell command authored per agent.

This build ships three deeply integrated web-app specialists (§What to build first):
  authorization  — BOLA/BOPLA/BFLA + tenant isolation via ownership matrices
  identity-session — login/MFA/recovery/session lifecycle/JWT/OAuth matrices
  workflow-state — business-logic invariants: skip-state, replay, self-approval
"""
from .loader import load_specialists, SPECIALIST_DIR
from .scheduler import Scheduler

__all__ = ["load_specialists", "Scheduler", "SPECIALIST_DIR"]
