#!/usr/bin/env python3
"""autoturret_bs2 — the BS2 arsenal adapter for the autoturret engine.

Makes autoturret a first-class BS2 backend tool ALONGSIDE ariadne (planner) and memoria (RAG),
with three things a BS2 arsenal tool needs:

  1. GOVERNANCE MAP  — TOOL_RISK + PHASE_ACTION_CLASS: how each lane maps onto BS2's action
     classes (net.recon / web.recon / web.exploit / ad.exploit) and risk ceiling, so shots fire
     under the campaign capability instead of beside the seam. Merge TOOL_RISK into the
     `tool_risk_registry=` passed to BattleApplication at battle setup.
  2. CONTENT-BLIND INVOCATION  — run(): launches the engine as a SUBPROCESS and reads back only
     run/recon.json (grounded facts + provenance + flags). Raw exploit output never enters the
     caller's context — the manager-isolation boundary holds by construction, not by discipline.
  3. STRATEGY ASSIST  — assist(): a short plaintext block for STRATEGY.md summarizing what
     autoturret PROVED, in the same advisory shape as memoria_assist.assist(). Never raises.

Nothing here touches a live campaign DB, the :8124 engine, or the War-Room front end. It only
proposes; the caller decides when/whether to fire, under its own governed capability.
"""
import json, os, subprocess, sys

ENGINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "autoturret.py")

# 1. GOVERNANCE MAP -----------------------------------------------------------------------------
# risk ceiling for the tool as a whole (merge into BattleApplication tool_risk_registry)
TOOL_RISK = {"autoturret": "high"}
# per-phase BS2 action class — a semi/manual dial gates the exploit/pivot classes; the recon
# floor (net/web.recon) is the safe auto-fire floor.
PHASE_ACTION_CLASS = {
    "recon": "net.recon", "enum": "web.recon",
    "exploit": "web.exploit", "loot": "host.access",
    "cred": "host.access", "pivot": "lateral.move", "own": "ad.exploit",
}
FLOOR = {"net.recon", "web.recon"}          # auto-fire on semi dial; everything else gated


def run(target, run_dir, dial="semi", ttl=600, timeout=None):
    """Fire autoturret at `target` as a content-blind subprocess. Returns run/recon.json as a
    dict: {owned, stopped, fired, hits, flags, proven_facts:[{fact,lane,evidence}], apps, ...}.
    The caller sees METADATA + short evidence only — raw output stays in run_dir/raw/ (browser).
    Never raises: returns {'error': ...} on failure so a strategist loop is never blocked."""
    os.makedirs(run_dir, exist_ok=True)
    env = dict(os.environ, AUTOTURRET_RUN=run_dir)
    try:
        subprocess.run([sys.executable, ENGINE, "--target", target, "--dial", dial,
                        "--ttl", str(ttl), "--run-dir", run_dir],
                       env=env, cwd=os.path.dirname(ENGINE),
                       capture_output=True, text=True, timeout=timeout or (ttl + 90))
    except subprocess.TimeoutExpired:
        pass                                # engine self-bounds by TTL; recon.json is still written
    except Exception as e:
        return {"error": f"autoturret launch failed: {e}"}
    try:
        with open(os.path.join(run_dir, "recon.json")) as f:
            return json.load(f)
    except Exception as e:
        return {"error": f"no recon.json ({e})"}


def assist(recon, max_block=1400):
    """A short 'ATTACK RESULTS' block for STRATEGY.md — advisory, same shape as memoria_assist.
    Pass either a recon dict (from run()) or a path to a recon.json. Never raises."""
    try:
        if isinstance(recon, str):
            with open(recon) as f:
                recon = json.load(f)
        if not isinstance(recon, dict) or recon.get("error"):
            return "(autoturret unavailable)"
        pf = recon.get("proven_facts") or []
        if not pf and not recon.get("flags"):
            return ""
        head = (f"ATTACK RESULTS (autoturret — GROUNDED facts only, advisory):\n"
                f"- status: {'OWNED' if recon.get('owned') else 'not owned'} "
                f"({recon.get('stopped','?')}); {recon.get('hits',0)}/{recon.get('fired',0)} lanes hit; "
                f"{len(recon.get('flags') or [])} flags")
        lines = [head]
        for p in pf[:24]:
            lines.append(f"- ⚑ {p['fact']}  (proved by {p['lane']})")
        block = "\n".join(lines)
        return block[:max_block - 3].rstrip() + "..." if len(block) > max_block else block
    except Exception:
        return "(autoturret unavailable)"


if __name__ == "__main__":
    # self-test on the last live run's artifact — no network, no engine launch
    import glob
    cands = sorted(glob.glob("/opt/bs2/run*/recon.json"), key=os.path.getmtime)
    if cands:
        print("TOOL_RISK =", TOOL_RISK)
        print("PHASE_ACTION_CLASS =", PHASE_ACTION_CLASS)
        print("-" * 60)
        print(assist(cands[-1]))
    else:
        print("no recon.json yet — run autoturret first")
