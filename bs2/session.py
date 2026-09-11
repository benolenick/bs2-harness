"""Bounded controlled checks and restart-aware manager context."""
import os
import shlex
import threading
from contextlib import contextmanager
from .journal import digest
from .memory import BattleMemory
from .verification import verify_read

_ENV_LOCK = threading.RLock()


@contextmanager
def environment(**values):
    # Legacy adapters use process env; serialize scoped overrides in this driver.
    with _ENV_LOCK:
        old = {k: os.environ.get(k) for k in values}
        os.environ.update({k: str(v) for k, v in values.items()})
        try:
            yield
        finally:
            for k, value in old.items():
                if value is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = value


def check_private_read(directory, *, base, route, identity_route, owner, other,
                       resource_id, private_contract, generation, session_epoch):
    """owner/other = (operator identity label, bearer token). At most five requests.

The operator supplies the private-resource policy and identity endpoint. A model
may choose which offered check to run, but cannot invent its controls or verdict.
"""
    from live import target_exec
    if not all(r.startswith("/") and not r.startswith("//") for r in (route, identity_route)):
        raise ValueError("check routes must be origin-relative")
    if not generation or not session_epoch or generation == "unknown" or session_epoch == "unknown":
        raise ValueError("explicit target generation and session epoch required")
    if owner[0] == other[0] or owner[1] == other[1] or not owner[1] or not other[1]:
        raise ValueError("two distinct provisioned principals and credentials required")
    base = base.rstrip("/")
    key = digest({"url": base + route, "method": "GET", "body": None})
    conditions = {"target_generation": generation, "session_epoch": session_epoch,
                  "principals": [owner[0], other[0]],
                  "credentials": [digest({"authorization": "Bearer " + p[1]}) for p in (owner, other)],
                  "private_contract": digest(private_contract)}
    memory = BattleMemory(directory)
    context = memory.context([route, "private resource"], conditions=conditions)
    retry = memory.retry(key, conditions)
    if retry["suppress"]:
        return {"verdict": "suppressed", **retry, "context_hash": context["context_hash"]}

    def request(path, principal):
        headers = ["-H", "Authorization: Bearer " + principal[1]] if principal[1] else []
        cmd = shlex.join(["curl", "-sS", "-i", *headers, base + path])
        with environment(BS2_RUN_DIR=directory, BS2_PRINCIPAL_ID=principal[0],
                         BS2_SESSION_EPOCH=session_epoch, BS2_TARGET_GENERATION=generation):
            output = target_exec.run(cmd, base, action_class="web.recon", timeout=10)
            receipt = getattr(target_exec._GOVERNANCE_CONTEXT, "last_receipt", None)
        if not receipt:
            raise RuntimeError(output[:300])
        return receipt["seq"]

    try:
        ai, bi = request(identity_route, owner), request(identity_route, other)
        a, b, c = request(route, owner), request(route, other), request(route, ("anonymous", ""))
    except RuntimeError as exc:
        memory.journal.append("inconclusive", {"reason": str(exc), "action_key": key, "conditions": conditions})
        memory.fold().close()
        return {"verdict": "inconclusive", "reason": str(exc)}
    return verify_read(directory, owner=a, other=b, anonymous=c, owner_identity=ai, other_identity=bi,
                       resource_id=resource_id, private_contract=private_contract, action_key=key)


def manager_context(frontier=()):
    directory = os.environ.get("BS2_RUN_DIR")
    if not directory:
        return "CAIRN unavailable: set BS2_RUN_DIR; target execution will refuse without durable receipts."
    return BattleMemory(directory).context(frontier, conditions={
        "target_generation": os.environ.get("BS2_TARGET_GENERATION", "unknown"),
        "session_epoch": os.environ.get("BS2_SESSION_EPOCH", "unknown")})["text"]


def record_manager_action(verb, argument):
    directory = os.environ.get("BS2_RUN_DIR")
    if directory:
        memory = BattleMemory(directory)
        memory.journal.append("hypothesis" if verb == "FINDING" else "decision",
                              {"verb": verb or "INVALID", "proposal_digest": digest(argument),
                               "claim": "Manager proposal only; requires independent evidence"})
        memory.fold().close()
