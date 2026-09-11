"""Read-only loopback operator view. No raw artifacts, arbitrary paths or write APIs."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .memory import BattleMemory


def server(directory, port=8130):
    memory = BattleMemory(directory)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            # Defend against DNS rebinding and cross-origin reads of local state.
            if self.headers.get("Host") not in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"):
                self.send_error(403)
                return
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.send_error(403)
                return
            try:
                if self.path == "/":
                    raw, mime = (Path(__file__).parent / "panel.html").read_bytes(), "text/html; charset=utf-8"
                elif self.path == "/panel.js":
                    raw, mime = (Path(__file__).parent / "panel.js").read_bytes(), "text/javascript"
                elif self.path == "/api/state":
                    raw, mime = json.dumps(memory.panel()).encode(), "application/json"
                elif self.path.startswith("/api/event/") and self.path[11:].isdigit():
                    seq = int(self.path[11:])
                    rows = memory.journal.events()
                    if not 1 <= seq <= len(rows):
                        self.send_error(404)
                        return
                    raw, mime = json.dumps(rows[seq-1], indent=2).encode(), "application/json"
                else:
                    self.send_error(404)
                    return
            except Exception:
                self.send_error(503, "Receipt projection unavailable; integrity must be checked")
                return
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(raw)
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", required=True)
    p.add_argument("--port", type=int, default=8130)
    args = p.parse_args()
    srv = server(args.run_dir, args.port)
    print(f"BS2 operator panel http://127.0.0.1:{srv.server_port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
