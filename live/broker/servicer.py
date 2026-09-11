#!/usr/bin/env python3
"""Finite policy approver. BS2_APPROVED_COMMAND_HASHES must name an operator-reviewed
JSON list of SHA256 hashes of exact command strings. This is NOT a human click."""
import hashlib, json, os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bs2.approval import write_decision


def main():
    allow_file = os.environ.get("BS2_APPROVED_COMMAND_HASHES")
    if not allow_file:
        raise SystemExit("Set BS2_APPROVED_COMMAND_HASHES to an exact-command hash list; otherwise use bs2_gate.py")
    hashes = set(json.loads(Path(allow_file).read_text()))
    state = Path(os.environ.get("BS2_BROKER_STATE", str(Path.home() / ".local/state/bs2-broker")))
    deadline = time.monotonic() + min(2400, int(os.environ.get("BS2_SERVICER_SECONDS", "300")))
    seen = set()
    while time.monotonic() < deadline:
        for path in sorted((state / "pending").glob("*.json")):
            if path.stem in seen:
                continue
            try:
                row = json.loads(path.read_text())
                if hashlib.sha256(row["command"].encode()).hexdigest() in hashes:
                    write_decision(state, path.stem, True, "exact command allowlist", actor="operator-policy")
                    print(f"policy approved {path.stem}", flush=True)
                    seen.add(path.stem)
            except (ValueError, OSError, KeyError):
                continue
        time.sleep(0.4)


if __name__ == "__main__":
    main()
