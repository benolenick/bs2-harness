#!/usr/bin/env python3
"""
bs2_client.py — zero-dep client for the Battlestation 2.0 governed server (:8124).

This is what wires the manager surface INTO BS2 2.0. The governed server already exposes
`POST /api/levers` with the same three actions this project uses (set_goal / set_hold /
set_directives) — and its `apply_lever` writes the SAME atrun flat files the autoturret
engine reads, PLUS a hash-chained `levers.audit.jsonl`. So routing a manager steer through
here makes it both GOVERNED (ledger + audit chain) and EFFECTIVE (the engine obeys the file).

Auth: the server is loopback-only and requires exact same-origin for mutations, so every
request must carry Host + (for POST) Origin naming this listener. No charter attestation is
needed for levers (that gates campaign advance / live execution, not steering).

stdlib only (urllib), so it runs anywhere manager_bridge does.
"""
from __future__ import annotations
import os, json, uuid, urllib.request, urllib.error
from urllib.parse import urlsplit

BS2_URL = os.environ.get("BS2_URL", "http://127.0.0.1:8124").rstrip("/")
# Where the governed server's apply_lever writes the lever files (must match the run the
# engine reads). Defaults to the double-barrel atrun, same as service.py apply_lever.
BS2_TELEMETRY_DIR = os.environ.get(
    "BS2_TELEMETRY_DIR", "/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria/atrun")


class BS2Error(Exception):
    pass


def _authority() -> str:
    s = urlsplit(BS2_URL)
    return s.netloc


def _req(method: str, path: str, body: dict | None = None, timeout: float = 6.0) -> dict:
    url = f"{BS2_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Host": _authority()}
    if method == "POST":
        headers["Content-Type"] = "application/json"
        headers["Origin"] = BS2_URL          # exact same-origin the server demands
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            raise BS2Error(f"HTTP {e.code} {path}") from e
        err = (payload or {}).get("error", {})
        raise BS2Error(err.get("message") or err.get("code") or f"HTTP {e.code}")
    except Exception as e:
        raise BS2Error(str(e)) from e
    if isinstance(payload, dict) and payload.get("ok") is False:
        err = payload.get("error", {})
        raise BS2Error(err.get("message") or err.get("code") or "request failed")
    return payload.get("data", payload) if isinstance(payload, dict) else payload


# --------------------------------------------------------------------------------- reads
def reachable(timeout: float = 2.0) -> bool:
    try:
        _req("GET", "/api/health", timeout=timeout)
        return True
    except Exception:
        return False


def health() -> dict:
    return _req("GET", "/api/health")


def battles() -> list:
    d = _req("GET", "/api/battles")
    return d if isinstance(d, list) else d.get("battles", [])


def workspace(battle_id: str, limit: int = 1) -> dict:
    return _req("GET", f"/api/battles/{battle_id}/workspace?limit={limit}")


def snapshot(battle_id: str) -> dict:
    return _req("GET", f"/api/battles/{battle_id}/snapshot")


# --------------------------------------------------------------------------------- writes
def lever(action: str, value=None) -> dict:
    """POST a governed lever. action in {set_goal,set_hold,set_directives}. Returns the
    server's lever-state result (includes the audit chain head)."""
    if action not in ("set_goal", "set_hold", "set_directives"):
        raise BS2Error(f"unknown lever action: {action}")
    body = {"action": action, "idempotency_key": uuid.uuid4().hex}
    if value is not None:
        body["value"] = value
    return _req("POST", "/api/levers", body)


def governed_summary(battle_id: str | None = None) -> dict:
    """A compact, safe view of the governed server for the StatusPacket."""
    out: dict = {"url": BS2_URL, "reachable": False}
    try:
        h = health()
        out.update({
            "reachable": True,
            "event_store": h.get("event_store"),
            "external_witness": h.get("external_witness"),
            "live_tool_execution": h.get("live_tool_execution"),
            "battle_count": h.get("battle_count"),
            "failed_battles": h.get("failed_battles"),
        })
    except Exception as e:
        out["error"] = str(e)
        return out
    try:
        out["battles"] = [{"battle_id": b.get("battle_id"), "status": b.get("status"),
                           "sequence": b.get("sequence")} for b in battles()]
    except Exception:
        pass
    bid = battle_id or os.environ.get("BS2_BATTLE")
    if bid:
        try:
            snap = workspace(bid).get("snapshot", {})
            out["battle"] = {k: snap.get(k) for k in
                             ("battle_id", "status", "title", "manager_generation",
                              "charter_hash", "roe_epoch") if k in snap}
        except Exception as e:
            out["battle_error"] = str(e)
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(governed_summary(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
