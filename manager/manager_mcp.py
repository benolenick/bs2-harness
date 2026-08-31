#!/usr/bin/env python3
"""
manager_mcp.py — MCP stdio server exposing the autoturret manager surface as first-class
tools the Opus manager MODEL calls directly (instead of hand-poking flat files).

This is the bridge Ben asked for: it turns the three levers + the grounded graph into a
callable tool surface. Register it with Claude Code (see manager/README.md) and the manager
session gets:

    manager_status         -> content-blind StatusPacket (owned/counts/apps/levers/review q)
    manager_set_goal       -> LEVER 2: set the planner goal
    manager_hold           -> LEVER 1: pause/resume sweeps
    manager_dispatch_trooper -> DRIVE: run one concrete trooper task now (manager-safe result)
    manager_fire_autoturret  -> DRIVE: fire one engine sweep now
    manager_add_directive  -> LEVER 3: inject abstract strategy into trooper objectives
    manager_review_queue   -> the unverifiable-claim handoff worklist
    manager_which_run      -> which run dir is active

Zero external dependencies: minimal JSON-RPC 2.0 over newline-delimited stdio (the MCP
stdio transport), so it runs under any python3 without `pip install mcp`.

Everything routes through manager_bridge.py, which enforces the content-blind scrub — the
manager can never pull a secret value through these tools.
"""
import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import manager_bridge as mb

SERVER = {"name": "autoturret-manager", "version": "1.0.0"}
PROTOCOL = "2024-11-05"

TOOLS = [
    {
        "name": "manager_status",
        "description": ("Content-blind snapshot of the live autoturret run: target, owned, stop "
                        "reason, fired/hits/flags counts, apps->vhost map, unlocked capability keys, "
                        "grounded non-secret facts, CAPTURED-secret counts (values withheld), current "
                        "lever state, and the review-queue count. Read this to decide your next "
                        "directive. Secret values (flags/creds/hashes) are never returned."),
        "inputSchema": {"type": "object", "properties": {
            "run_dir": {"type": "string", "description": "Run dir; omit to auto-select the newest active run."}}},
    },
    {
        "name": "manager_set_goal",
        "description": ("LEVER 2 — set the planner goal the engine pursues on its next iteration. "
                        "Examples: 'rce', 'rce_as:drupal', 'root', 'read_file:/etc/passwd', "
                        "'flag'. This is a strategic aim, not a command."),
        "inputSchema": {"type": "object", "properties": {
            "goal": {"type": "string"},
            "run_dir": {"type": "string"}}, "required": ["goal"]},
    },
    {
        "name": "manager_hold",
        "description": ("LEVER 1 — pause (on=true) or resume (on=false) sweeps between iterations, "
                        "e.g. while you reconfigure goal/directives."),
        "inputSchema": {"type": "object", "properties": {
            "on": {"type": "boolean"},
            "run_dir": {"type": "string"}}, "required": ["on"]},
    },
    {
        "name": "manager_add_directive",
        "description": ("LEVER 3 — append an ABSTRACT, content-blind strategy line that is injected "
                        "into every trooper objective (e.g. 'prioritise dev.* for source/cred leaks; "
                        "chain git leak -> creds -> authed footholds'). Never put a secret or an exact "
                        "command here — state intent; the trooper picks the tools."),
        "inputSchema": {"type": "object", "properties": {
            "text": {"type": "string"},
            "run_dir": {"type": "string"}}, "required": ["text"]},
    },
    {
        "name": "manager_review_queue",
        "description": ("The handoff worklist: cards the engine could NOT verify autonomously "
                        "(indeterminate gates, unproven compromise claims). Safe fields only "
                        "(card/phase/reason/rc) — raw output pointers are not returned."),
        "inputSchema": {"type": "object", "properties": {
            "run_dir": {"type": "string"}}},
    },
    {
        "name": "manager_which_run",
        "description": "Return the run dir the tools will act on (the newest active run unless run_dir is given).",
        "inputSchema": {"type": "object", "properties": {
            "run_dir": {"type": "string"}}},
    },
    {
        "name": "manager_dispatch_trooper",
        "description": ("DRIVE: tell a trooper exactly what to do NOW. You write the concrete "
            "objective (which tool/technique, against which host/path); one trooper executes it "
            "on-target and returns manager-safe telemetry (observed/tried/blocked/next), safe "
            "fact strings, and secret-fact KEY COUNTS (values withheld). You direct; the trooper "
            "issues the on-target commands. Use for a targeted probe the autonomous sweep isn't "
            "covering (e.g. 'check http://dev.inlanefreight.local/.git/HEAD and dump it if 200')."),
        "inputSchema": {"type": "object", "properties": {
            "objective": {"type": "string", "description": "Concrete task incl. the tool/technique to use."},
            "target": {"type": "string", "description": "Override target IP (default: the run's target)."},
            "model": {"type": "string", "description": "Override trooper model (default: engine default)."},
            "run_dir": {"type": "string"}},
            "required": ["objective"]},
    },
    {
        "name": "manager_fire_autoturret",
        "description": ("DRIVE: fire the autoturret engine NOW — one bounded proof-gated card sweep "
            "against the run's target. If the engine is already sweeping this run (the double-barrel "
            "loop), it will NOT stack a duplicate; it ensures the engine isn't paused and reports the "
            "in-flight run. Optionally set the planner goal for this sweep (e.g. 'rce_as:drupal', "
            "'root'). Content-blind: operator-tier output goes to a log file, never to you."),
        "inputSchema": {"type": "object", "properties": {
            "goal": {"type": "string", "description": "Planner goal for this sweep, e.g. rce_as:drupal|root."},
            "dial": {"type": "string", "enum": ["manual", "semi", "full"], "description": "Autonomy dial (default full)."},
            "ttl": {"type": "integer", "description": "Max seconds for the sweep (default 900)."},
            "run_dir": {"type": "string"}}},
    },
]


def _call(name: str, args: dict):
    rd = args.get("run_dir")
    if name == "manager_status":
        return mb.build_status(rd).to_dict()
    if name == "manager_set_goal":
        return mb.set_goal(args.get("goal", ""), rd)
    if name == "manager_hold":
        return mb.set_hold(bool(args.get("on")), rd)
    if name == "manager_add_directive":
        return mb.add_directive(args.get("text", ""), rd)
    if name == "manager_review_queue":
        return mb.read_review_queue(rd)
    if name == "manager_which_run":
        return {"run_dir": mb.find_run(rd)}
    if name == "manager_dispatch_trooper":
        return mb.dispatch_trooper(args.get("objective", ""), rd,
                                   target=args.get("target"), model=args.get("model"))
    if name == "manager_fire_autoturret":
        return mb.fire_autoturret(rd, goal=args.get("goal"),
                                  dial=args.get("dial", "full"), ttl=int(args.get("ttl", 900)))
    raise ValueError(f"unknown tool: {name}")


def _result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle(msg: dict):
    """Return a response dict, or None for notifications."""
    method = msg.get("method")
    id_ = msg.get("id")
    if method == "initialize":
        return _result(id_, {"protocolVersion": PROTOCOL,
                             "capabilities": {"tools": {}},
                             "serverInfo": SERVER})
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return _result(id_, {})
    if method == "tools/list":
        return _result(id_, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            out = _call(name, args)
            return _result(id_, {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]})
        except Exception as e:
            return _result(id_, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
    if id_ is not None:
        return _error(id_, -32601, f"method not found: {method}")
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
