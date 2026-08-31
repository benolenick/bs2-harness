#!/usr/bin/env python3
"""ab_runner — the blind, reset-state A/B harness for MIT claude-pentest vs BS2
(2026-08-25). Implements the protocol from /mnt/sata/crapi/HANDOFF.md:

    crapi reset -> run harness -> record claimed solves -> crapi reset ->
    run the other harness -> record -> diff both against the SAME reference scorer.

The reference scorer (/mnt/sata/crapi/scorer/crapi_score.py) is the answer key: it
exploits the 8 auto-gradeable challenges end-to-end on a fresh board and reports
SOLVED/UNSOLVED/SKIP with exact endpoint + evidence. This module never invents scoring
— it ORCHESTRATES the documented protocol and merges the reference scoreboard with the
harness's own claimed findings. All side-effectful steps (reset, launch, scorer) go
through injectable runners so tests never touch a target.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import time

GUNBELT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJ_RE = re.compile(r"\[(final|report)\] .*projection=[a-z_]+")
PROJ_VAL = re.compile(r"projection=([a-z_]+)")
RUN_DIR_RE = re.compile(r"run_dir=(\S+)")


# ---- target reset + health (the HANDOFF contract) -----------------------------

def reset_target(shell=subprocess.run):
    """`crapi reset`: compose down -v && up -d on the ISOLATED daemon (wipes all state
    — attacker/victim accounts, coupons, videos). Never touches the main dockerd.
    Returns True only on exit 0 — a failed reset must ABORT the run, never silently
    run a side on a dirty board."""
    res = shell(["crapi", "reset"], capture_output=True, text=True, timeout=600)
    return getattr(res, "returncode", 0) == 0


def wait_healthy(base="http://127.0.0.1:8888", timeout=180, opener=None,
                 sleep=time.sleep):
    """Poll the target root until the gateway answers 200 (fresh board is up)."""
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with (opener or urllib.request.urlopen)(base + "/", timeout=5) as f:
                if f.status == 200:
                    return True
        except Exception:
            pass
        sleep(3)
    return False


# ---- one governed BS2 side ----------------------------------------------------

def launch_bs2(steps, shell=subprocess.run):
    """Reuse scripts/launch_lab.sh (seam open + governed launch) — ONE canonical launch
    path, no duplication. Returns (runbase, log_path)."""
    out = shell(["bash", f"{GUNBELT}/scripts/launch_lab.sh", "crapi", str(steps)],
                capture_output=True, text=True, timeout=300)
    runbase, log = None, None
    for line in (out.stdout or "").splitlines():
        if line.startswith("RUNBASE="):
            runbase = line.split("=", 1)[1].strip()
        if "launched:" in line:
            m = re.search(r"log (\S+)", line)
            if m:
                log = m.group(1)
    if not runbase or not log:
        raise RuntimeError(f"launch_lab.sh did not report RUNBASE/log: {out.stdout!r} "
                           f"{out.stderr!r}")
    return runbase, log


def wait_terminal(log_path, poll_s=30, grace_s=30, max_wait=1800, sleep=time.sleep):
    """The hardened terminal detection (lab pass-4 lesson), as a library: projection
    event on the log -> report.json (exists only at terminal time) -> pid death with a
    grace pass. Returns {"kind", "projection"} where kind is one of
    projection|report|late|process_gone|timeout."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        txt = _read(log_path)
        if txt and PROJ_RE.search(txt):
            m = PROJ_VAL.search(txt)
            return {"kind": "projection", "projection": m.group(1) if m else None}
        rjson = os.path.join(os.path.dirname(log_path), "report.json")
        if os.path.exists(rjson):
            try:
                proj = json.load(open(rjson)).get("terminal_projection") or {}
                p = proj.get("projection") if isinstance(proj, dict) else None
                return {"kind": "report", "projection": p}
            except Exception:
                return {"kind": "report", "projection": None}
        pidfile = os.path.join(os.path.dirname(log_path), "RUN.pid")
        if os.path.exists(pidfile):
            try:
                pid = int(open(pidfile).read().strip())
            except Exception:
                pid = None
            if pid and not _alive(pid):
                sleep(grace_s)                     # terminal writes can land a beat late
                txt = _read(log_path)
                if txt and PROJ_RE.search(txt):
                    m = PROJ_VAL.search(txt)
                    return {"kind": "late", "projection": m.group(1) if m else None}
                if os.path.exists(rjson):
                    try:
                        proj = json.load(open(rjson)).get("terminal_projection") or {}
                        return {"kind": "late", "projection":
                                proj.get("projection") if isinstance(proj, dict) else None}
                    except Exception:
                        pass
                return {"kind": "process_gone", "projection": None}
        sleep(poll_s)
    return {"kind": "timeout", "projection": None}


def _read(path):
    try:
        return open(path).read()
    except Exception:
        return ""


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


# ---- artifact collection ------------------------------------------------------

def _engagement_dir(runbase):
    """run_htb writes the map/report to a sibling engagement dir named by run identity;
    find it via the launch log's [final] run_dir= or by globbing the pattern."""
    log = os.path.join(runbase, "run.log")
    if os.path.exists(log):
        m = RUN_DIR_RE.search(_read(log))
        if m and os.path.isdir(m.group(1)):
            return m.group(1)
    import glob
    cands = glob.glob(os.path.join(os.path.dirname(runbase),
                                   f"htb-*-{os.path.basename(runbase).split('-')[-1]}"))
    return cands[0] if cands else None


def collect_artifacts(runbase, side, out_dir, steps_cap, model="", term=None,
                      shell=subprocess.run):
    """Normalize one side's run into ab_artifacts/<out_dir>: report.json (engagement
    report incl. findings), map.json (cartography), run.meta.json (wall-clock, steps,
    projection, outcome, coverage), scoreboard.json (the reference answer key run on
    this same fresh board). Returns the artifact dir."""
    import shutil
    os.makedirs(out_dir, exist_ok=True)
    eng = _engagement_dir(runbase)
    for name, src in (("report.json", f"{eng}/report.json" if eng else ""),
                      ("map.json", f"{eng}/cartography.json" if eng else "")):
        if src and os.path.exists(src):
            shutil.copy(src, f"{out_dir}/{name}")
    report = {}
    try:
        report = json.load(open(f"{out_dir}/report.json"))
    except Exception:
        pass
    summary = report.get("executive_summary") or {}
    meta = {
        "side": side,
        "target": report.get("target", "http://127.0.0.1:8888"),
        "model": model,
        "steps_cap": steps_cap,
        "started": report.get("started") or report.get("generated_ts"),
        "wall_s": None,
        "steps_used": None,
        "coverage_pct": summary.get("coverage_pct"),
        "findings_count": len(report.get("findings") or []),
        "findings_by_severity": summary.get("findings_by_severity") or {},
        "complete": summary.get("complete"),
        "projection": (term or {}).get("projection"),
        "terminal_kind": (term or {}).get("kind"),
        "objective_achieved": summary.get("objective_achieved"),
    }
    # wall time + steps from the launch log (the [final] event carries them)
    log = os.path.join(runbase, "run.log")
    if os.path.exists(log):
        txt = _read(log)
        m = re.search(r"\[final\] .*steps_used=(\d+)", txt)
        meta["steps_used"] = int(m.group(1)) if m else None
    json.dump(meta, open(f"{out_dir}/run.meta.json", "w"), indent=1)
    # the answer key on THIS board (fresh at run time; the harness may have mutated it
    # since — the scorer re-provisions its own users, so it still grades 8/8)
    r = shell(["python3", "/mnt/sata/crapi/scorer/crapi_score.py", "--json"],
              capture_output=True, text=True, timeout=900)
    sb = os.path.join(os.path.dirname("/mnt/sata/crapi/scorer/crapi_score.py"),
                      "scoreboard.json")
    if os.path.exists(sb):
        shutil.copy(sb, f"{out_dir}/scoreboard.json")
    json.dump({"scorer_stdout_tail": (r.stdout or "")[-500:],
               "scorer_stderr_tail": (r.stderr or "")[-300:]},
              open(f"{out_dir}/scorer_run.json", "w"), indent=1)
    return out_dir


def run_side(side, steps, out_dir, reset=True, model="", launch_fn=None,
             shell=subprocess.run, opener=None, sleep=time.sleep):
    """The full HANDOFF protocol for one side. launch_fn(runbase) is an optional
    post-launch hook (e.g. the MIT harness launch); None = the BS2 governed launch."""
    if reset and not reset_target(shell=shell):
        return {"error": "crapi reset failed"}
    if not wait_healthy(opener=opener, sleep=sleep):
        return {"error": "target never became healthy after reset"}
    if launch_fn is None:
        runbase, log = launch_bs2(steps, shell=shell)
    else:
        runbase, log = launch_fn(steps)
    term = wait_terminal(log, sleep=sleep)
    if term["kind"] == "timeout":
        return {"error": "run did not reach a terminal state in time"}
    collect_artifacts(runbase, side, out_dir, steps_cap=steps, model=model,
                      term=term, shell=shell)
    return {"out_dir": out_dir, "terminal": term, "runbase": runbase}


__all__ = ["reset_target", "wait_healthy", "launch_bs2", "wait_terminal",
           "collect_artifacts", "run_side"]
