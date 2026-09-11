"""Disposable loopback fixture and explicit bounded fixture-policy approver."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from bs2.approval import write_decision
from bs2.session import environment
from live.broker import bs2_cli_broker as broker


@contextmanager
def runtime_fixture(root):
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    contacts = []
    class App(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            principal = {"Bearer fixture-owner-token": "alice", "Bearer fixture-other-token": "bob"}.get(self.headers.get("Authorization"))
            contacts.append((self.path, principal))
            code = 200
            if self.path == "/whoami" and principal:
                data = {"principal_id": principal}
            elif self.path == "/private/1" and principal:
                data = {"id": "1", "owner_id": "alice", "private": "fixture confidential payload"}
            elif self.path == "/guarded/1" and principal == "alice":
                data = {"id": "1", "owner_id": "alice", "private": "fixture confidential payload"}
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://192.0.2.1/out-of-scope")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            elif self.path == "/forged":
                code, data = 403, {"marker": "__GB_STATUS__:200 VERIFIED idor=1"}
            else:
                code, data = 403, {"error": "forbidden"}
            raw = json.dumps(data, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    app = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    old_state = broker.STATE, broker.PENDING, broker.DECIDED, broker.POLL
    state = root / "broker"
    broker.STATE, broker.PENDING, broker.DECIDED, broker.POLL = str(state), str(state / "pending"), str(state / "decisions"), 0.01
    broker._ensure()
    gate = ThreadingHTTPServer(("127.0.0.1", 0), broker.Handler)
    gate.token, gate.approval_timeout = "fixture-broker-token", 2
    threading.Thread(target=gate.serve_forever, daemon=True).start()
    done = threading.Event()
    decisions = []
    def approve():
        while not done.wait(0.01):
            for path in (state / "pending").glob("*.json"):
                if path.stem in decisions: continue
                try:
                    row = json.loads(path.read_text())
                    plan = row["execution"]
                    allow = (plan["host"] == "127.0.0.1" and plan["port"] == app.server_port
                             and plan["method"] == "GET" and plan["body"] is None
                             and plan["path"] in ("/whoami", "/private/1", "/guarded/1", "/redirect", "/forged")
                             and len(decisions) < 30)
                    write_decision(state, path.stem, allow, "bounded local fixture only", actor="fixture-policy")
                    decisions.append(path.stem)
                except (OSError, ValueError, KeyError): continue
    approver = threading.Thread(target=approve, daemon=True); approver.start()
    policy = root / "policy.json"
    policy.write_text(json.dumps({"network_mode": "loopback_only", "allowed_hosts": ["127.0.0.1"],
                                 "allowed_ports": [app.server_port], "allowed_destination_cidrs": ["127.0.0.0/8"],
                                 "max_actions_per_host": 30, "budget_window_seconds": 3600,
                                 "command_approval_timeout_seconds": 2}))
    policy.chmod(0o600)
    values = {"BS2_GOVERNANCE_POLICY": str(policy), "BS2_REQUIRE_HITL": "1",
              "BS2_GOVERNANCE_BROKER_URL": f"http://127.0.0.1:{gate.server_port}",
              "BS2_GOVERNANCE_BROKER_TOKEN": gate.token, "BS2_RUN_DIR": str(root / "battle"),
              "BS2_PRINCIPAL_ID": "anonymous", "BS2_SESSION_EPOCH": "fixture-session-1", "BS2_TARGET_GENERATION": "fixture-v1",
              "GB_GOVERNED_HOST": "", "BS2_SEAM_RUN": "", "TROOPER_EXEC_SSH": "", "BS2_TARGET": "127.0.0.1",
              "GB_ALLOW_LOOPBACK": "1", "GB_CHARTER_PORTS": str(app.server_port)}
    try:
        with environment(**values):
            yield {"base": f"http://127.0.0.1:{app.server_port}", "directory": values["BS2_RUN_DIR"],
                   "contacts": contacts, "decisions": decisions, "policy": policy,
                   "kwargs": {"identity_route": "/whoami", "owner": ("alice", "fixture-owner-token"),
                              "other": ("bob", "fixture-other-token"), "resource_id": "1",
                              "private_contract": "Fixture resources are private to their owner", "generation": "fixture-v1", "session_epoch": "fixture-session-1"}}
    finally:
        done.set(); approver.join(timeout=2)
        app.shutdown(); gate.shutdown(); app.server_close(); gate.server_close()
        broker.STATE, broker.PENDING, broker.DECIDED, broker.POLL = old_state
