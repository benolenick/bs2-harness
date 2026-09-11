"""Controlled private-resource read proof. No stdout marker or model verdict is trusted."""
from .journal import digest
from .memory import BattleMemory
import time


def verify_read(directory, *, owner, other, anonymous, owner_identity, other_identity,
                resource_id, private_contract, action_key=None):
    """Arguments identify journal receipts, not caller-supplied response dictionaries.

private_contract is an operator-supplied assertion that the resource is private;
without an application policy contract, a cross-owner read isn't a vulnerability.
Identity controls must be authenticated /whoami-style responses carrying
principal_id, from the SAME credential, session epoch, generation and destination.
"""
    memory = BattleMemory(directory)
    events = {r["seq"]: r for r in memory.journal.events()}
    refs = [owner, other, anonymous, owner_identity, other_identity]
    result = {"verdict": "inconclusive", "reason": "missing or unusable controls", "receipt_seqs": refs,
              "action_key": action_key or digest([resource_id, private_contract]), "conditions": {}}
    rows = [events.get(i) for i in refs]
    if all(r and r["kind"] == "observation" and time.time() - r["ts"] <= 300 for r in rows):
        a, b, c, ai, bi = [r["payload"] for r in rows]
        result["action_key"] = action_key or a["request_key"]
        result["conditions"] = {"target_generation": a["target_generation"], "session_epoch": a["session_epoch"],
                                "principals": [a["principal"], b["principal"]],
                                "credentials": [a["credential_fingerprint"], b["credential_fingerprint"]],
                                "private_contract": digest(private_contract)}
        same_environment = all(p.get(k) == a.get(k) for p in (b, c, ai, bi)
                               for k in ("target_generation", "session_epoch", "destination", "port"))
        identities = (ai["status"] == bi["status"] == 200
                      and ai.get("identity", {}).get("principal_id") == a["principal"]
                      and bi.get("identity", {}).get("principal_id") == b["principal"]
                      and a["principal"] != b["principal"]
                      and a["credential_fingerprint"] == ai["credential_fingerprint"]
                      and b["credential_fingerprint"] == bi["credential_fingerprint"]
                      and a["credential_fingerprint"] != b["credential_fingerprint"]
                      and a["credential_fingerprint"] != digest({}) and b["credential_fingerprint"] != digest({}))
        baseline = (same_environment and identities and private_contract.strip()
                    and a["target_generation"] != "unknown" and a["session_epoch"] != "unknown"
                    and a["request_key"] == b["request_key"] == c["request_key"]
                    and a["method"] == b["method"] == c["method"] == "GET"
                    and a["status"] == 200 and a["body_bytes"] > 0
                    and a.get("identity", {}).get("id") == str(resource_id)
                    and a.get("identity", {}).get("owner_id") == a["principal"]
                    and c["principal"] == "anonymous" and c["credential_fingerprint"] == digest({})
                    and c["status"] in (401, 403, 404))
        if baseline and b["status"] == 200 and a["body_sha256"] == b["body_sha256"]:
            result.update(verdict="confirmed", reason="Other authenticated principal read the same private resource; anonymous denied")
        elif baseline and b["status"] in (401, 403, 404):
            result.update(verdict="negative", reason="Owner succeeded; other principal and anonymous denied under these conditions")
        else:
            result["reason"] = "Controls, identity, resource, policy, or environment did not establish a comparable private read"
    row = memory.journal.append("verification", result)
    memory.fold().close()
    return {**result, "source_seq": row["seq"]}
