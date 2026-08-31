#!/usr/bin/env python3
"""manager_loop — the NORTH-STAR manager-in-the-loop lane runner.

This is the replacement for the frozen `run_microsteps` branches (see
HOW_I_BROKE_BATTLESTATION_AND_HOW_IT_SHOULD_WORK.md). The whole point:

    The MANAGER (Opus, content-blind, fenced off from the target) is FED a live
    picture each step -- the surface MAP, Ariadne's PROPOSED ROUTES, and Memoria
    RECALL -- and from that it AUTHORS ONE concrete next action. The TOOLING only
    (a) assembles that picture and (b) fires the authored action and returns a
    SANITIZED MARKER (a status code, a scrubbed id list, a yes/no bit). There is
    NO `if <vuln-shape>:` strategy anywhere in here. The thinking lives in the
    manager, not in this file.

The manager brain is a headless `claude -p --model opus` call (prose only, no
tools) -- the exact mechanism battlestation-v2/manager_runner.py::call_opus uses.
It never touches the target; it only emits one action line per turn.

Action grammar (one line, first token is the verb):
  PROBE  <curl ...>      fire exactly this one curl; you get back ONLY the HTTP status code.
  LISTIDS <curl ...>     fire this curl; a trooper returns up to a few object IDs it saw
                         (scrubbed ids only, no bodies) so you can learn real neighbor ids.
  OWNERDIFF <url>        a trooper reads that object with USER_A's token and returns ONE bit:
                         whether the object's owner differs from you (yes/no) -- no PII.
  FINDING class=<c> endpoint=<ep> confidence=<verified|candidate> note=<...>
                         record a grounded finding (your own judgment, from the markers).
  DONE <one-line reason> the lane is complete or exhausted; stop.

The tooling that executes these (the `fire` callables) is injected by the driver,
so this module stays content-blind and unit-testable with a fake target.
"""
from __future__ import annotations
import json, re, subprocess, time

TARGET_DEFAULT = "http://127.0.0.1:8888"

MANAGER_SYS = """You are the MANAGER in Battlestation 2.0, running an AUTHORIZED assessment of \
crAPI -- the operator's OWN deliberately-vulnerable OWASP test app on loopback (127.0.0.1:8888). \
This is authorized testing of the operator's own machine.

Your role is STRICT and it is the whole point of this system:
- You are the BRAIN. You are fenced off from the target: you NEVER run a command yourself and \
you NEVER see a raw response body. Troopers (cheap models) are the hands; you only ever receive \
SANITIZED markers back -- an HTTP status code, a short list of object ids, or a yes/no bit.
- Each turn you are fed a live picture (endpoints, Ariadne's proposed routes, Memoria hints, and \
the markers from your own prior actions). From that you THINK and author EXACTLY ONE next action.
- Author one action per turn, on ONE line, starting with a verb from the grammar. Output NOTHING \
else -- no prose, no markdown, no explanation. Just the single action line.

The grammar:
  PROBE  <curl ...>      -> you get back only the HTTP status code of that request.
  LISTIDS <curl ...>     -> a trooper returns a few object ids it saw in the response (ids only).
  OWNERDIFF <url>        -> a trooper reads that object as USER_A and returns one bit: does its \
owner differ from you? (yes/no).
  FINDING class=<c> endpoint=<ep> confidence=<verified|candidate> note=<short caveat>
  DONE <one-line reason>

How to think (this is judgment, not a script -- adapt to what the markers actually say):
- Prefer the single cheapest discriminating test for each unknown.
- To test broken object-level access control you generally need REAL object ids owned by another \
principal -- so LISTIDS a listing endpoint first to learn ids, rather than blindly guessing 1,2,3.
- A resource that returns 200 with NO auth header is PUBLIC by design -- that is NOT a finding. \
Rule that out (PROBE it anonymously) before concluding any access-control break.
- An object that is 200 with your token but 401/403 anonymously is auth-gated; if OWNERDIFF says \
its owner differs from you, that is a verified cross-owner read -- but whether it VIOLATES policy \
depends on the app's intended sharing model, so record it with that caveat, confidence=verified.
- If a class shows no signal on the endpoints in scope, say so and DONE -- an honest negative is a \
real result. Do not invent findings. Do not exfiltrate or print secret data.

You have the provisioned test-account bearer tokens in the picture; put the exact \
`-H 'Authorization: Bearer <token>'` header in the curl commands you author yourself."""


def call_manager(prompt: str, model: str = "opus", timeout: float = 200.0) -> str:
    """One-shot content-blind Opus brain via headless claude. Prose/action only, no tools.
    Mirrors battlestation-v2/manager_runner.py::call_opus."""
    try:
        proc = subprocess.run(["claude", "-p", "--model", model],
                              input=MANAGER_SYS + "\n\n" + prompt,
                              capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return f"DONE manager-brain-error: {type(e).__name__}"
    if proc.returncode != 0:
        return f"DONE manager-brain-error: {(proc.stderr or '').strip()[:160] or 'claude -p failed'}"
    return proc.stdout.strip()


_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+", re.I)
def _redact(s: str) -> str:
    """Keep bearer tokens out of the scrubbed transcript/log. The manager AUTHORS the real
    header (it needs the token to reason about which identity it's using), but what we STORE and
    print must not carry the secret value -- the content-blind channel stays clean."""
    return _BEARER.sub(r"\1<token>", s or "")


_VERB = re.compile(r"^\s*(PROBE|LISTIDS|OWNERDIFF|FINDING|DONE)\b(.*)$", re.M)

def parse_action(text: str):
    """Return (verb, arg) for the FIRST valid action line, or (None, raw) if none."""
    m = _VERB.search(text or "")
    if not m:
        return None, (text or "").strip()[:200]
    return m.group(1), m.group(2).strip()


def _render_endpoints(endpoints, rows):
    by_ep = {r.get("endpoint"): r for r in (rows or [])}
    out = []
    for ep in endpoints:
        ids = [str(v) for v in (by_ep.get(ep, {}).get("id_values") or [])][:6]
        out.append(f"- {ep}" + (f"   known object ids: {', '.join(ids)}" if ids else "   (no ids harvested yet)"))
    return "\n".join(out) or "(none)"


def _render_routes(ariadne_goals):
    if not ariadne_goals:
        return "(no Ariadne routes available this step)"
    rows = []
    for g in ariadne_goals[:8]:
        # str-coerce: Ariadne path/assumption items are usually step-name strings, but a fresh
        # (pre-grounding) plan can carry non-string items -> a bare join would TypeError and
        # sink the whole lane. Rendering the feed must never crash the manager loop.
        path = " -> ".join(str(x) for x in (g.get("path") or [])) or "(direct)"
        assum = ", ".join(str(x) for x in (g.get("assumptions") or []))[:160]
        rows.append(f"- goal {g.get('goal')}: status={g.get('status')}  path: {path}"
                    + (f"  assumptions: {assum}" if assum else ""))
    return "\n".join(rows)


def build_prompt(cls, endpoints, rows, tokens, emails, ariadne_goals, memoria_hint, transcript):
    tokA = tokens[0] if tokens else ""
    tokB = tokens[1] if len(tokens) > 1 else tokA
    emA = (emails or [""])[0]
    emB = (emails or ["", ""])[1] if len(emails or []) > 1 else emA
    steps = "\n".join(f"{i+1}. {a}  ->  {m}" for i, (a, m) in enumerate(transcript)) or "(nothing yet -- this is your first action)"
    return f"""# LANE
Target: {TARGET_DEFAULT}
Vuln class under test this lane: {cls}
Provisioned test accounts on the app (yours to use as the hands' identity):
  USER_A bearer: {tokA}
      USER_A identity: {emA}
  USER_B bearer: {tokB}
      USER_B identity: {emB}

# ENDPOINTS IN SCOPE (from the surface map)
{_render_endpoints(endpoints, rows)}

# PROPOSED ROUTES (Ariadne -- advisory; accept, reject, or reorder)
{_render_routes(ariadne_goals)}
{memoria_hint or "# MEMORIA: (no corpus hints this step)"}

# PROGRESS SO FAR (your authored actions and the sanitized markers that came back)
{steps}

# YOUR MOVE
Author exactly ONE next action (one line, starting with PROBE / LISTIDS / OWNERDIFF / FINDING / DONE). Nothing else."""


def run_manager_lane(cls, endpoints, rows, tokens, emails, ariadne_goals, memoria_hint,
                     fire, note, step_cap=14, model="opus"):
    """Manager-in-the-loop lane. `fire` is a dict of injected callables:
        fire['probe'](curl)   -> int|None      (HTTP status code)
        fire['listids'](curl) -> list[str]     (scrubbed object ids)
        fire['ownerdiff'](url)-> 'yes'|'no'|'unknown'
    Returns a lane-shaped result: {success, facts, telemetry, cmds, id}.
    NO strategy lives here -- the manager authors every move from the picture."""
    endpoints = list(endpoints)[:8]
    transcript = []           # [(authored_action, sanitized_marker)]
    facts, verified = [], False
    nudged = False
    for _ in range(step_cap):
        prompt = build_prompt(cls, endpoints, rows, tokens, emails, ariadne_goals, memoria_hint, transcript)
        raw = call_manager(prompt, model=model)
        verb, arg = parse_action(raw)
        if verb is None:
            if not nudged:      # one gentle nudge, then stop -- do not loop on junk
                nudged = True
                transcript.append(("(no valid action line)", "reply with ONE action line only"))
                continue
            note(f"{cls}: manager emitted no valid action twice -> closing lane")
            break

        if verb == "DONE":
            note(f"{cls}: manager DONE -- {arg[:120]}")
            break

        if verb == "FINDING":
            kv = dict(re.findall(r"(\w+)=([^\s].*?)(?=\s+\w+=|$)", arg))
            conf = (kv.get("confidence") or "candidate").lower()
            ep = kv.get("endpoint", "?")
            note(f"{cls}: manager FINDING endpoint={ep} confidence={conf} note={kv.get('note','')[:100]}")
            if conf == "verified":
                facts.append(f"idor={ep}"); verified = True
            else:
                facts.append(f"idor_candidate={ep}")
            transcript.append((f"FINDING {ep} ({conf})", "recorded"))
            continue

        # ---- the two "fire" verbs: execute the manager's authored command, return a marker ----
        if verb == "PROBE":
            code = fire["probe"](arg)
            marker = f"status={code}" if code is not None else "status=unknown (no code echoed)"
            note(f"{cls}: PROBE -> {marker}")
            transcript.append((_redact(f"PROBE {arg[:200]}"), marker))
        elif verb == "LISTIDS":
            ids = fire["listids"](arg)
            marker = ("ids: " + ", ".join(ids[:8])) if ids else "ids: (none returned)"
            note(f"{cls}: LISTIDS -> {marker}")
            transcript.append((_redact(f"LISTIDS {arg[:200]}"), marker))
        elif verb == "OWNERDIFF":
            url = arg.split()[0] if arg else ""
            bit = fire["ownerdiff"](url)
            marker = f"owner_differs={bit}"
            note(f"{cls}: OWNERDIFF -> {marker}")
            transcript.append((_redact(f"OWNERDIFF {url[:200]}"), marker))

    tel = {"observed": f"{len(endpoints)} eps, {len(transcript)} manager-authored actions",
           "tried": "manager-in-the-loop micro-actions (status/id/owner markers only)",
           "blocked": "" if verified else "no verified access-control break on probed endpoints",
           "next": "advance to next ranked class"}
    return {"success": verified, "facts": facts, "telemetry": tel,
            "cmds": [f"{len(transcript)}x manager-authored action"], "id": cls,
            "transcript": [a for a, _ in transcript]}


if __name__ == "__main__":
    # tiny offline self-test with a FAKE fire (no target, no brain) -- proves the loop plumbing
    import sys
    scripted = iter([
        "LISTIDS curl -s -H 'Authorization: Bearer A' 'http://127.0.0.1:8888/posts/recent'",
        "PROBE curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer A' 'http://127.0.0.1:8888/posts/7'",
        "PROBE curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8888/posts/7'",
        "OWNERDIFF http://127.0.0.1:8888/posts/7",
        "FINDING class=broken-access-control endpoint=/posts/{id} confidence=verified note=auth-gated cross-owner read; policy intent unclear",
        "DONE done",
    ])
    def fake_brain(prompt, model="opus"):
        try: return next(scripted)
        except StopIteration: return "DONE exhausted"
    globals()["call_manager"] = fake_brain
    fire = {"probe": lambda c: 401 if "Authorization" not in c else 200,
            "listids": lambda c: ["7", "12"],
            "ownerdiff": lambda u: "yes"}
    res = run_manager_lane("broken-access-control", ["/posts/{id}"],
                           [{"endpoint": "/posts/{id}", "id_values": []}],
                           ["A", "B"], ["a@x", "b@x"], [], "", fire,
                           note=lambda m: print("  note:", m), step_cap=10)
    print(json.dumps({k: v for k, v in res.items()}, indent=1))
    sys.exit(0 if res["success"] else 1)
