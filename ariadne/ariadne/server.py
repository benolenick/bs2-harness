"""Ariadne HTTP service -- the attack-path planner the BS2 manager consults.

Stdlib only (no Flask). Loads the operator corpus + knowledge once at startup, then
serves plan / recon / extract / exploits over JSON on :8112 (ARIADNE_PORT to change).
Any client reaches it the same way (curl); see ariadne/README.md.

Endpoints:
  GET  /health                         -> {status, operators, knowledge, exploits}
  POST /plan     {target|graph, top}   -> ranked grounded/relaxed paths
  POST /recon    {target|graph, steps} -> observable facts to confirm next
  POST /extract  {notes, name}         -> validated fact-graph (LLM)
  GET  /exploits?q=<kw|CVE>&limit=N    -> Exploit-DB matches

A `graph` is {goal:[...], facts:[[...]], negatives:[[...]]}; or pass {"target":"name"}
to load targets/<name>.yaml.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ariadne.loader import load_operators, load_knowledge, load_target, _t   # noqa: E402
from ariadne.model import Target                                             # noqa: E402
from ariadne.planner import Planner                                          # noqa: E402
from ariadne.frontier import recon_plan                                      # noqa: E402
from ariadne.schema import load_predicates, validate_fact                    # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = os.path.join(HERE, "targets")

OPS = load_operators()
KNOW = load_knowledge()
PREDS = load_predicates()
MAX_BODY = 1_000_000
MAX_FACTS = 10_000


def _corpus_hash():
    """Fingerprint only the reviewed/live planner corpus, never staged candidates."""
    paths = [
        os.path.join(HERE, "ariadne", "corpus", "operators.yaml"),
        os.path.join(HERE, "ariadne", "corpus", "predicates.yaml"),
    ]
    knowledge = os.path.join(HERE, "ariadne", "corpus", "knowledge")
    for root, _, names in os.walk(knowledge):
        paths.extend(os.path.join(root, name) for name in names if name.endswith(".yaml"))
    digest = hashlib.sha256()
    for path in sorted(paths):
        rel = os.path.relpath(path, HERE).encode()
        digest.update(len(rel).to_bytes(4, "big")); digest.update(rel)
        with open(path, "rb") as handle:
            data = handle.read()
        digest.update(len(data).to_bytes(8, "big")); digest.update(data)
    return digest.hexdigest()


CORPUS_HASH = _corpus_hash()


def _bounded_int(value, name, default, lo, hi):
    try:
        parsed = int(default if value is None else value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not lo <= parsed <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return parsed


def _validated_graph(graph):
    if not isinstance(graph, dict):
        raise ValueError("graph must be an object")
    allowed = {"name", "goal", "facts", "negatives", "notes"}
    unknown = set(graph) - allowed
    if unknown:
        raise ValueError(f"unknown graph fields: {sorted(unknown)}")
    facts = graph.get("facts", [])
    negatives = graph.get("negatives", [])
    if not isinstance(facts, list) or not isinstance(negatives, list):
        raise ValueError("facts and negatives must be arrays")
    if len(facts) > MAX_FACTS or len(negatives) > MAX_FACTS:
        raise ValueError(f"facts and negatives are limited to {MAX_FACTS} each")
    goal = graph.get("goal")
    ok, why = validate_fact(goal, PREDS)
    if not ok:
        raise ValueError(f"invalid goal: {why}")
    for label, items in (("fact", facts), ("negative", negatives)):
        for index, item in enumerate(items):
            ok, why = validate_fact(item, PREDS)
            if not ok:
                raise ValueError(f"invalid {label} {index}: {why}")
    notes = graph.get("notes", "")
    if not isinstance(notes, str) or len(notes) > 50_000:
        raise ValueError("notes must be a string of at most 50000 characters")
    name = graph.get("name", "api")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
        raise ValueError("graph name is invalid")
    return graph


def _target_from_req(body):
    """Build a Target from either {"target":"name"} or an inline {"graph":{...}}."""
    if body.get("target"):
        name = body["target"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name):
            raise ValueError("target must be a registered target name, not a path")
        path = os.path.join(TARGETS, f"{name}.yaml")
        return load_target(path)
    g = _validated_graph(body.get("graph") or body)
    return Target(
        name=g.get("name", "api"),
        facts=set(_t(f) for f in g.get("facts", [])),
        negatives=set(_t(n) for n in g.get("negatives", [])),
        goal=_t(g["goal"]),
        notes=g.get("notes", ""),
    )


def _sol_json(sol):
    return {
        "assumptions": [list(a) for a in sol.assumptions],
        "steps": [{"name": o.name, "desc": o.desc, "cost": o.cost, "refs": o.refs} for o in sol.ops],
        "cost": sum(o.cost for o in sol.ops),
    }


def do_plan(body):
    t = _target_from_req(body)
    p = Planner(t, OPS, knowledge=KNOW)
    plans = p.plan(top_k=_bounded_int(body.get("top"), "top", 5, 1, 20))
    return {
        "target": t.name, "goal": list(t.goal),
        "grounded": sum(1 for s in plans if not s.assumptions),
        "budget_hit": p.budget_hit,
        "corpus_hash": CORPUS_HASH,
        "paths": [_sol_json(s) for s in plans],
    }


def do_recon(body):
    t = _target_from_req(body)
    res = recon_plan(t, OPS, max_steps=_bounded_int(body.get("steps"), "steps", 12, 1, 50))
    return {"target": t.name, "goal": list(t.goal),
            "corpus_hash": CORPUS_HASH,
            "solved": res["solved"],
            "confirm_next": [{"fact": s["confirm"], "unblocks": s["unblocks"]} for s in res["steps"]]}


def do_extract(body):
    from ariadne.extract import extract      # imported lazily (hits the LLM)
    if not isinstance(body.get("notes"), str) or not 1 <= len(body["notes"]) <= 100_000:
        raise ValueError("notes must be a non-empty string of at most 100000 characters")
    res = extract(body["notes"], name=body.get("name"))
    return {"target": res["target"], "rejected": [list(r) if isinstance(r, tuple) else r
                                                  for r in res["rejected"]]}


def do_exploits(qs):
    from ariadne.exploits import search
    q = (qs.get("q") or [""])[0]
    limit = int((qs.get("limit") or ["25"])[0])
    return {"query": q, "matches": search(q, limit=limit)}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            # A timed-out caller is not a server failure and must not trigger a
            # second attempted error response (the old path produced traceback storms).
            return False
        return True

    def log_message(self, *a):
        pass  # quiet

    def do_GET(self):
        u = urlparse(self.path)
        try:
            if u.path == "/health":
                self._send(200, {"status": "ok", "operators": len(OPS),
                                 "knowledge": len(KNOW), "service": "ariadne",
                                 "api_schema": 1, "corpus_hash": CORPUS_HASH,
                                 "extractor_status": "not_health-checked"})
            elif u.path == "/exploits":
                self._send(200, do_exploits(parse_qs(u.query)))
            else:
                self._send(404, {"error": "no such route", "routes": ["/health", "/plan", "/recon", "/extract", "/exploits"]})
        except ValueError as e:
            self._send(400, {"error": str(e), "kind": "validation"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n < 0 or n > MAX_BODY:
                self._send(413, {"error": f"request body exceeds {MAX_BODY} bytes"})
                return
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("request body must be a JSON object")
            u = urlparse(self.path).path
            if u == "/plan":
                self._send(200, do_plan(body))
            elif u == "/recon":
                self._send(200, do_recon(body))
            elif u == "/extract":
                self._send(200, do_extract(body))
            else:
                self._send(404, {"error": "no such route"})
        except ValueError as e:
            self._send(400, {"error": str(e), "kind": "validation"})
        except Exception as e:
            self._send(500, {"error": str(e)})


def main():
    port = int(os.environ.get("ARIADNE_PORT", "8112"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ariadne serving on 127.0.0.1:{port}  ({len(OPS)} operators, {len(KNOW)} knowledge facts)",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
