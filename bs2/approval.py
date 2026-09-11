"""Exact, expiring, single-use approval records shared by all approver surfaces."""
import json
import os
from pathlib import Path
import re
import time
from .journal import canonical, digest


def validate_request(body):
    if not isinstance(body, dict):
        return False
    value = {k: v for k, v in body.items() if k != "request_digest"}
    return (body.get("request_digest") == digest(value)
            and bool(re.fullmatch(r"[0-9a-f]{32}", str(body.get("nonce", ""))))
            and isinstance(body.get("expires_at"), (int, float))
            and time.time() < body["expires_at"] <= time.time() + 610
            and body.get("execution", {}).get("backend") == "pinned-http-v1")


def write_decision(state, rid, allow, reason="operator", actor="operator"):
    if not re.fullmatch(r"[0-9a-f]{16}", rid):
        raise ValueError("invalid approval id")
    root = Path(state)
    request = json.loads((root / "pending" / f"{rid}.json").read_text())
    if time.time() >= request["expires_at"]:
        raise ValueError("approval request expired")
    data = {"allow": bool(allow), "reason": reason, "actor": actor, "ts": time.time(),
            "request_digest": request["request_digest"], "nonce": request["nonce"],
            "expires_at": request["expires_at"]}
    folder = root / "decisions"
    folder.mkdir(mode=0o700, exist_ok=True)
    tmp = folder / (rid + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(canonical(data))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, folder / (rid + ".json"))
    return data
