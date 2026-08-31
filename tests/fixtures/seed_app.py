#!/usr/bin/env python3
"""Localhost-only benchmark app with three deliberately seeded authorization flaws."""
from __future__ import annotations

from flask import Flask, jsonify, request


TOKENS = {"fixture-user-a": 1, "fixture-user-b": 2}


def create_app():
    app = Flask(__name__)
    app.config["ACCOUNTS"] = {
        1: {"id": 1, "email": "a@example.test", "balance": 100, "role": "user"},
        2: {"id": 2, "email": "b@example.test", "balance": 200, "role": "user"},
    }

    def principal():
        header = request.headers.get("Authorization", "")
        return TOKENS.get(header.removeprefix("Bearer "))

    @app.get("/api/accounts/<int:account_id>")
    def account(account_id):
        if principal() is None:
            return jsonify(error="authentication required"), 401
        # Seeded BOLA: any authenticated principal receives any account object.
        obj = app.config["ACCOUNTS"].get(account_id)
        return (jsonify(obj), 200) if obj else (jsonify(error="not found"), 404)

    @app.patch("/api/accounts/<int:account_id>")
    def patch_account(account_id):
        if principal() is None:
            return jsonify(error="authentication required"), 401
        data = request.get_json(silent=True) or {}
        obj = app.config["ACCOUNTS"].get(account_id)
        if obj is None:
            return jsonify(error="not found"), 404
        # Seeded mass assignment: the hidden role field is accepted and applied.
        updated = []
        for key in ("display_name", "role"):
            if key in data:
                obj[key] = data[key]
                updated.append(key)
        response = {"updated": updated}
        if "role" in updated:
            response["role"] = obj["role"]
        return jsonify(response)

    @app.post("/api/transfer")
    def transfer():
        if principal() is None:
            return jsonify(error="authentication required"), 401
        data = request.get_json(silent=True) or {}
        start, end = data.get("from_state"), data.get("to_state")
        # Seeded BFLA/workflow bypass: draft can jump directly to settled.
        if (start, end) == ("draft", "settled"):
            return jsonify(state="settled", skipped=True), 200
        if (start, end) == ("approved", "settled"):
            return jsonify(error="approval role required"), 403
        return jsonify(state=end or start or "draft"), 200

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=0)
