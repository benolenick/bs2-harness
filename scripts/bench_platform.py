#!/usr/bin/env python3
"""Repeatable localhost benchmark for the BS2 differential HTTP platform."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "live"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import appmodel
import differential
import lab
import session_vault
from observation import ObservationRecord
from seed_app import create_app
from werkzeug.serving import make_server

TOKEN_BY_PRINCIPAL = {"user:user-1": "fixture-user-a", "user:user-2": "fixture-user-b"}


class FixtureServer:
    def __enter__(self):
        self.server = make_server("127.0.0.1", 0, create_app())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.thread.join(timeout=2)


def _request(base, method, route, principal="anon", body=None):
    headers = {"Content-Type": "application/json"}
    token = TOKEN_BY_PRINCIPAL.get(principal)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + route, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        response = urllib.request.urlopen(req, timeout=2)
        status, raw, response_headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        status, raw, response_headers = exc.code, exc.read(), exc.headers
    try:
        value = json.loads(raw.decode())
    except Exception:
        value = {}
    keys = sorted(value) if isinstance(value, dict) else []
    return {"status": status, "schema_keys": keys,
            "headers": {name: "redacted" for name in response_headers.keys()},
            "size": len(raw), "ms": 1}


def _model_and_vault():
    model = appmodel.ApplicationModel(tempfile.mkdtemp())
    model.fold([
        "endpoint=GET /api/accounts/{id} auth=user object_type=account",
        "endpoint=PATCH /api/accounts/{id} auth=user object_type=account",
        "endpoint=POST /api/transfer auth=user",
        "object=account:1 owner=user:user-1 endpoint_id=ep-1",
        "object=account:2 owner=user:user-2 endpoint_id=ep-1",
        "workflow=transfer draft->approved->settled via=ep-3",
        "identity=user:user-1 session=s-1",
        "identity=user:user-2 session=s-2",
    ])
    vault = session_vault.SessionVault(tempfile.mkdtemp())
    vault.register("user", refs={"token": "fixture-token-ref-a"})
    vault.register("user", refs={"token": "fixture-token-ref-b"})
    return model, vault


def run_benchmark():
    model, vault = _model_and_vault()
    with FixtureServer() as fixture:
        ep = next(e for e in model.endpoints.values() if e["method"] == "GET")

        def runner(spec):
            # The transport resolves refs locally; no token value enters a BS2 record.
            account_id = 1 if spec["principal"] == "anon" else 2
            return _request(fixture.base, "GET", f"/api/accounts/{account_id}",
                            spec["principal"])

        sessions = [{"principal": "anon", "kind": "anon", "refs": {}}]
        sessions += sorted(vault.sessions.values(), key=lambda value: value["principal"])
        matrix = differential.matrix(ep, sessions, runner)
        matrix_bola = any(row.get("delta", {}).get("candidate") == "BOLA" for row in matrix)

        record = ObservationRecord(
            target="localhost-fixture",
            endpoint={"id": ep["id"], "method": "GET",
                      "route_template": "/api/accounts/{id}"},
            principal="user:user-1", map_node=ep["id"], tool={"name": "benchmark"},
            evidence=["fixture:bola"])
        lab_record = lab.run(record, model, vault, runner=runner)
        bola = matrix_bola and lab_record.response_delta.get("candidate") == "BOLA"

        mass_control = _request(fixture.base, "PATCH", "/api/accounts/1", "user:user-1",
                                {"display_name": "Alice"})
        mass_test = _request(fixture.base, "PATCH", "/api/accounts/1", "user:user-1",
                             {"role": "admin"})
        mass = differential.compare(mass_control, mass_test,
                                    owner_context={"owns_object": True})["candidate"] \
            == "mass-assignment"

        flow_control = _request(fixture.base, "POST", "/api/transfer", "user:user-1",
                                {"from_state": "approved", "to_state": "settled"})
        flow_test = _request(fixture.base, "POST", "/api/transfer", "user:user-1",
                             {"from_state": "draft", "to_state": "settled"})
        bfla = differential.compare(flow_control, flow_test)["candidate"] == "BFLA/BOPLA"

    detected = {"BOLA": bool(bola), "mass-assignment": bool(mass), "BFLA": bool(bfla)}
    return {"flaws": detected, "detected": sum(detected.values()), "known": len(detected)}


def main():
    result = run_benchmark()
    for name, found in result["flaws"].items():
        print(f"{name}: {'detected' if found else 'not-detected'}")
    print(f"score: {result['detected']}/{result['known']}")
    return 0 if result["detected"] == result["known"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
