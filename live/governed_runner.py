#!/usr/bin/env python3
"""governed_runner — the HTTP transport that makes the differential/lab engines REAL
(re-audit P1-2 vertical slice, 2026-08-25): compiles a request_spec into a curl command
and executes it through the §10.1 governed door (target_exec.run), parsing the result
into the normalized response record {status, headers, schema_keys, body, ms}.

The runner is what plugs `differential.replay` / `matrix` / `lab.run` into the governed
seam: every replay request is a governed work order, not an ungoverned curl.

Secrets discipline:
- session cookie JARS ride as references (-b <path>), never as values;
- other auth material (bearer tokens) may ride in spec['headers'] to authenticate the
  TRANSPORT, but response records keep header NAMES only, the door audits cmd_sha only,
  and nothing here persists a header value (do not set GB_RAW_LOG when authenticated
  sessions run through — raw capture is operator-authorized full visibility).
"""
from __future__ import annotations
import json
import re
import shlex
import time

try:
    import target_exec as TEXEC
except ImportError:                      # live/ imported as a package
    from . import target_exec as TEXEC

STATUS_RE = re.compile(r"__GB_STATUS__:(\d{3})")
TIME_RE = re.compile(r"__GB_TIME__:([\d.]+)")


def compile_curl(spec, timeout=30):
    """request_spec -> one bash-safe curl command string (quoted, one line).

    {id}-style template vars bind from path_binding. A cookie-jar REF in session_ref
    becomes `-b <path>` (the jar lives on the exec host; the value never enters the
    command). Read-only by contract: GET/HEAD; mutations require an explicit method in
    the spec AND survive the seam's risk ceiling anyway."""
    method = (spec.get("method") or "GET").upper()
    headers = dict(spec.get("headers") or {})
    base = spec.get("base") or ""
    route = spec.get("route_template") or "/"
    for k, v in (spec.get("path_binding") or {}).items():
        route = route.replace("{" + str(k) + "}", str(v))
    parts = ["curl", "-sS", "--max-time", str(int(timeout)), "-X", method,
             "-i",   # response headers + body; parsed back into names below
             "-w", "\\n__GB_STATUS__:%{http_code} __GB_TIME__:%{time_total}"]
    jar = ((spec.get("session_ref") or {}).get("cookies") or "").strip()
    if jar:
        parts += ["-b", jar]
    for k, v in headers.items():
        parts += ["-H", f"{k}: {v}"]
    body = spec.get("body")
    if body:
        parts += ["--data", json.dumps(body)]
    parts += [base + route]
    return " ".join(shlex.quote(p) for p in parts)


def parse_response(out, spec=None):
    """curl -i + -w trailer output -> the normalized response record. Denied/blocked
    governed outputs (target-exec markers) come back as {status: 0, error: ...}."""
    out = str(out or "")
    if out.startswith("["):
        return {"status": 0, "headers": {}, "schema_keys": [], "body": "", "ms": 0.0,
                "error": out[:200]}
    matches = list(STATUS_RE.finditer(out))
    m = matches[-1] if matches else None
    status = int(m.group(1)) if m else 0
    matches = list(TIME_RE.finditer(out))
    tm = matches[-1] if matches else None
    ms = round(float(tm.group(1)) * 1000, 1) if tm else 0.0
    header_names = {}
    for line in out.splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            break
        if ":" in line and not line.startswith(("HTTP/", "__GB_")):
            k, _, v = line.partition(":")
            header_names[k.strip().lower()] = v.strip()
    body = out.split("\r\n\r\n", 1)[-1].split("\n\n", 1)[-1]
    body = re.sub(r"\n__GB_STATUS__:.*$", "", body, flags=re.S).strip()
    return {"status": status, "headers": header_names,
            "schema_keys": _top_keys(body), "body": body, "ms": ms}


def _top_keys(body):
    keys = []
    try:
        d = json.loads(body)
        if isinstance(d, dict):
            keys = [str(k) for k in d.keys()]
    except Exception:
        keys = re.findall(r"\"([A-Za-z_][A-Za-z0-9_]*)\"\s*:", body)[:60]
    return sorted(keys)


def make_runner(timeout=30, target_exec_run=None):
    """runner(request_spec) -> normalized response record — the injectable transport
    for differential.replay/matrix and lab.run. Every request is a governed work order
    (action_class='web.recon' — read-only lane)."""
    run = target_exec_run or TEXEC.run

    def runner(spec):
        cmd = compile_curl(spec, timeout=timeout)
        out = run(cmd, target=(spec.get("base") or "").strip(),
                  action_class="web.recon", timeout=timeout + 15)
        rec = parse_response(out, spec)
        rec["receipt"] = f"gcurl-{int(time.time() * 1000)}"
        return rec
    return runner


__all__ = ["compile_curl", "parse_response", "make_runner"]
