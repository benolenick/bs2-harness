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
import hashlib, hmac, json, os, sys, time, sqlite3
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bs2.approval import validate_request
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
        self.connection.settimeout(10)
        tok = self.headers.get("X-BS2-Broker-Token", "")
        if not hmac.compare_digest(tok, self.server.token):
            return self._send(403, {"error": {"code": "bad_token"}})
        try:
            n = int(self.headers.get("Content-Length", 0))
            if not 0 < n <= 65536:
                raise ValueError("request length out of bounds")
            body = json.loads(self.rfile.read(n))
            if not validate_request(body):
                raise ValueError("invalid exact execution binding")
        except Exception:
            return self._send(400, {"error": {"code": "malformed_request"}})

        # Durable nonce consumption prevents replay across concurrent requests
        # and broker restarts. A retry needs a fresh request and fresh approval.
        con = sqlite3.connect(os.path.join(STATE, "nonces.sqlite3"), timeout=10)
        try:
            with con:
                con.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires REAL NOT NULL)")
                con.execute("INSERT INTO nonces VALUES(?,?)", (body["nonce"], body["expires_at"]))
        except sqlite3.IntegrityError:
            return self._send(409, {"error": {"code": "replayed_request"}})
        finally:
            con.close()

        rid = _req_id(body)
        record = {**body, "id": rid, "ts": time.time()}
        with os.fdopen(os.open(os.path.join(PENDING, rid + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
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

        deadline = min(time.time() + self.server.approval_timeout, body["expires_at"])
        dpath = os.path.join(DECIDED, rid + ".json")
        while time.time() < deadline:
            if os.path.exists(dpath):
                try:
                    with open(dpath) as f: dec = json.load(f)
                except Exception:
                    return self._send(200, {"data": {"allowed": False,
                                                      "status": "malformed_decision"}})
                bound = all(dec.get(k) == body[k] for k in ("request_digest", "nonce", "expires_at"))
                allowed = dec.get("allow") is True and bound and time.time() < deadline
                # consume pending
                try: os.remove(os.path.join(PENDING, rid + ".json"))
                except OSError: pass
                status = "approved" if allowed else "denied_or_binding_mismatch"
                return self._send(200, {"data": {"allowed": allowed, "status": status,
                                                  "id": rid, **{k: body[k] for k in ("request_digest", "nonce", "expires_at")}}})
            time.sleep(POLL)
        # timeout => fail closed
        try: os.remove(os.path.join(PENDING, rid + ".json"))
        except OSError: pass
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
    if host != "127.0.0.1":
        raise SystemExit("broker must bind 127.0.0.1; use a private tunnel for remote operators")
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
