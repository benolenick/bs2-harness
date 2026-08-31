#!/usr/bin/env python3
"""BS2 CLI approval broker — the backend-only operator gate.

Replaces the web Governance center as the decision surface for the physically
exclusive target door (live/target_exec.py :: _command_approval). It speaks the
EXACT contract target_exec expects:

  POST <url>  header X-BS2-Broker-Token: <token>
  body  {command,target,action_class,timeout,resolved_ips,run_id,assessment_id,...}
  resp  {"data":{"allowed":true}}            -> execute
        {"data":{"allowed":false,"status":"denied"}} -> fail-closed deny

Each box-touching request is written to <state>/pending/<id>.json and the HTTP
handler BLOCKS until the operator drops <state>/decisions/<id>.json (written by
bs2_approve.py). Timeout, malformed decision, or shutdown => deny (fail-closed).

The token is compared in constant time; a wrong/absent token => 403 deny.
"""
import hashlib, hmac, json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = os.environ.get("BS2_BROKER_STATE",
    os.path.expanduser("~/.local/state/bs2-broker"))
PENDING = os.path.join(STATE, "pending")
DECIDED = os.path.join(STATE, "decisions")
TOKEN_FILE = os.path.join(STATE, "token")
POLL = 0.4

def _ensure():
    os.makedirs(PENDING, exist_ok=True); os.makedirs(DECIDED, exist_ok=True)
    os.chmod(STATE, 0o700)

def _req_id(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon + str(time.time_ns()).encode()).hexdigest()[:16]

class Handler(BaseHTTPRequestHandler):
    server_version = "bs2-broker/1"
    def log_message(self, *a): pass  # quiet

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        tok = self.headers.get("X-BS2-Broker-Token", "")
        if not hmac.compare_digest(tok, self.server.token):
            return self._send(403, {"error": {"code": "bad_token"}})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
        except Exception:
            return self._send(400, {"error": {"code": "malformed_request"}})

        rid = _req_id(body)
        record = {"id": rid, "ts": time.time(), **body}
        with open(os.path.join(PENDING, rid + ".json"), "w") as f:
            json.dump(record, f, indent=2)
        os.chmod(os.path.join(PENDING, rid + ".json"), 0o600)

        # Human-visible line on the broker console (the operator's live feed).
        ips = ",".join(body.get("resolved_ips") or []) or "-"
        sys.stderr.write(
            f"\n\033[1;33m[APPROVAL NEEDED {rid}]\033[0m "
            f"class={body.get('action_class')} target={body.get('target')} ips={ips}\n"
            f"    $ {body.get('command')}\n"
            f"    approve: bs2-approve allow {rid}   deny: bs2-approve deny {rid}\n")
        sys.stderr.flush()

        deadline = time.time() + self.server.approval_timeout
        dpath = os.path.join(DECIDED, rid + ".json")
        while time.time() < deadline:
            if os.path.exists(dpath):
                try:
                    with open(dpath) as f: dec = json.load(f)
                except Exception:
                    return self._send(200, {"data": {"allowed": False,
                                                      "status": "malformed_decision"}})
                allowed = dec.get("allow") is True
                # consume pending
                try: os.remove(os.path.join(PENDING, rid + ".json"))
                except OSError: pass
                status = "approved" if allowed else dec.get("reason", "denied")
                return self._send(200, {"data": {"allowed": allowed, "status": status,
                                                  "id": rid}})
            time.sleep(POLL)
        # timeout => fail closed
        return self._send(200, {"data": {"allowed": False, "status": "approval_timeout",
                                         "id": rid}})

def main():
    _ensure()
    token = os.environ.get("BS2_GOVERNANCE_BROKER_TOKEN")
    if not token:
        token = hashlib.sha256(os.urandom(32)).hexdigest()
    with open(TOKEN_FILE, "w") as f: f.write(token)
    os.chmod(TOKEN_FILE, 0o600)
    host = os.environ.get("BS2_BROKER_HOST", "127.0.0.1")
    port = int(os.environ.get("BS2_BROKER_PORT", "8129"))
    approval_timeout = int(os.environ.get("BS2_BROKER_APPROVAL_TIMEOUT", "300"))
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.token = token; srv.approval_timeout = approval_timeout
    sys.stderr.write(f"bs2-broker up http://{host}:{port}  state={STATE}\n"
                     f"  token file: {TOKEN_FILE}\n")
    sys.stderr.flush()
    srv.serve_forever()

if __name__ == "__main__":
    main()
