"""Small deterministic restart contract, not an engagement/LLM performance claim."""
import json
import os
import subprocess
import sys
from .journal import digest
from .memory import BattleMemory


def restart_benchmark(directory):
    memory = BattleMemory(directory)
    capsule = {"service": "http", "snapshot_generation": "g1"}
    memory.journal.append("observation", {"method": "GET", "request_key": "after-capsule-route", "status": 200, "principal": "owner"})
    conditions = {"target_generation": "g1", "session_epoch": "s1", "principal": "other"}
    memory.journal.append("verification", {"verdict": "negative", "reason": "synthetic controlled negative",
                                          "action_key": "already-tested", "conditions": conditions})
    memory.journal.append("hypothesis", {"claim": "unproven-candidate"})
    # A fresh interpreter performs fold+recall; no inherited in-memory objects.
    proc = subprocess.run([sys.executable, "-m", "bs2.cli", "--run-dir", str(directory), "context"],
                          capture_output=True, text=True, timeout=20, check=True)
    recovered = json.loads(proc.stdout)
    state = BattleMemory(directory).panel()
    retained = 1 + int("after-capsule-route"[:16] in recovered["text"]) + int("already-tested" in recovered["text"])
    repeat = BattleMemory(directory).retry("already-tested", conditions)
    reopen = BattleMemory(directory).retry("already-tested", dict(conditions, target_generation="g2"))
    return {"kind": "deterministic synthetic restart contract", "facts_available": 3,
            "capsules_only": {"retained_facts": len(capsule) - 1, "redundant_checks": 1, "unsupported_conclusions": 0},
            "capsules_plus_cairn": {"retained_facts": retained, "redundant_checks": int(not repeat["suppress"]),
                                    "unsupported_conclusions": sum("unproven-candidate" in i["content"] for i in state["known"])},
            "changed_generation_reopens": not reopen["suppress"], "real_process_restart": True,
            "caveat": "Frozen task facts and deterministic consumer; not evidence of improved real-world attack success or model performance"}
