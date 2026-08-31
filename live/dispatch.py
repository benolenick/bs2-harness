#!/usr/bin/env python3
"""dispatch — the DISPATCH stage: fan per-class EXPERTS over the worklist, through gexec.

The Laketree verdict: the pieces already cover every capability; the gap was orchestration.
This is the expert-lane runner + the control surface Ben asked for:

  * a LEVEL dial (L0 map-only .. L3 deep) that presets which experts run and their budgets
  * per-expert on/off toggles that override the preset
  * a master ARM spend-safety: nothing at L1+ runs unless armed (default DISARMED + L0)

Every expert's target-touching command goes THROUGH gexec (governed); confirmed findings are
recorded as governed evidence + verify. State lives in experts/experts.json.

Subcommands:
  list                      show master (armed/level) + per-expert state
  arm | disarm              master spend-safety
  level <0|1|2|3>           set level -> apply preset (enabled set + budgets)
  on <class|all> | off ...  per-expert toggle (overrides preset)
  plan  --run-dir DIR       DRY: what WOULD run at current level (0 spend, always allowed)
  run   --run-dir DIR       dispatch enabled experts (REFUSES unless armed AND level>=2)
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys, time
from pathlib import Path
try:
    import reflex_loop as _reflex
except Exception:
    _reflex = None
try:
    from memoria_enrich import hints_for as _memoria_hints
except Exception:
    _memoria_hints = None

GB = Path("/opt/bs2/live")
EXPERTS_DIR = GB / "experts"
REG = EXPERTS_DIR / "experts.json"
CLASSES = ["sqli", "nosqli", "broken-access-control", "auth-bypass", "path-traversal", "xss", "llm-injection"]

# LEVEL presets: (enabled classes, minutes/expert, max_turns/expert, parallel-allowed, note)
LEVELS = {
    0: (set(),                                                      0,   0,  False, "MAP-ONLY — mapper+planner, zero attack spend (always safe)"),
    1: (set(),                                                      0,   0,  False, "LIGHT — deterministic RECIPE lane only (no LLM experts); run via `cockpit recipe`"),
    2: ({"sqli", "auth-bypass", "broken-access-control"},          8, 200,  False, "MEDIUM — top-3 experts, short budget, sequential"),
    3: (set(CLASSES),                                              12, 250,  True,  "DEEP — all experts, full budget, escalation, --parallel allowed"),
}

def load():
    return json.loads(REG.read_text())

def save(reg):
    REG.write_text(json.dumps(reg, indent=2))

def apply_level(reg, lvl):
    enabled, minutes, turns, parallel, note = LEVELS[lvl]
    reg["_master"]["level"] = lvl
    for cls in CLASSES:
        e = reg["experts"].setdefault(cls, {})
        e["enabled"] = cls in enabled
        if minutes:
            e["minutes"] = minutes
            e["max_turns"] = turns
    reg["_master"]["parallel_allowed"] = parallel
    return note

# ------------------------------------------------------------------ display
def cmd_list(a):
    reg = load(); m = reg["_master"]
    lvl = m.get("level", 0)
    print(f"● dispatch control  —  master: {'ARMED' if m.get('armed') else 'DISARMED (no spend)'}   level: L{lvl}")
    print(f"  L{lvl}: {LEVELS[lvl][4]}")
    print(f"  total-minutes cap: {m.get('total_minutes_cap','-')}   default model: {m.get('default_model','-')}   parallel-allowed: {m.get('parallel_allowed',False)}")
    print(f"  memoria hints: {'ON' if m.get('memoria') else 'off'}   (corpus advisor -> expert briefs)")
    print(f"  RISK ceiling: {m.get('risk','safe')}   (orthogonal to level: bounds acceptable IMPACT, not spend)")
    print("  experts:")
    for cls in CLASSES:
        e = reg["experts"].get(cls, {})
        on = "ON " if e.get("enabled") else "off"
        mdl = e.get("model") or m.get("default_model", "")
        print(f"    [{on}] {cls:22} {e.get('minutes','?')}m  turns={e.get('max_turns','?')}  model={mdl}")
    est = sum(reg["experts"][c].get("minutes", 0) for c in CLASSES if reg["experts"][c].get("enabled"))
    print(f"  → if run now: {sum(1 for c in CLASSES if reg['experts'][c].get('enabled'))} experts, ~{est} min budget"
          + ("" if m.get("armed") and lvl >= 2 else "   (blocked: " + ("disarm" if not m.get('armed') else f"L{lvl} has no expert lane") + ")"))

def cmd_arm(a):
    reg = load(); reg["_master"]["armed"] = True; save(reg)
    print("● master ARMED — armed expert runs at level>=2 will now spend. `dispatch disarm` to lock.")
def cmd_disarm(a):
    reg = load(); reg["_master"]["armed"] = False; save(reg)
    print("● master DISARMED — no expert spend possible until re-armed.")

def cmd_level(a):
    reg = load(); note = apply_level(reg, a.n); save(reg)
    print(f"● level set: L{a.n} — {note}")
    cmd_list(a)

def cmd_risk(a):
    reg = load(); reg["_master"]["risk"] = a.level; save(reg)
    print(f"● risk ceiling set: {a.level}  (readonly=recon only · safe=+non-destructive exploit · full=+destructive)")

def cmd_memoria(a):
    reg = load(); reg["_master"]["memoria"] = (a.op == "on"); save(reg)
    print(f"● Memoria hints {a.op.upper()} — expert briefs will {'' if a.op=='on' else 'NOT '}be armed with corpus techniques")

def cmd_toggle(a):
    reg = load(); who = a.who.lower()
    val = (a.op == "on")
    targets = CLASSES if who == "all" else [who]
    for t in targets:
        if t not in reg["experts"]:
            print(f"  ! unknown expert {t!r} (have: {', '.join(CLASSES)})"); continue
        reg["experts"][t]["enabled"] = val
    save(reg)
    print(f"● {a.op} {who} — override applied atop L{reg['_master'].get('level',0)} preset")
    cmd_list(a)

# ------------------------------------------------------------------ worklist -> brief
def worklist_by_class(run_dir):
    wl = json.loads((Path(run_dir) / "worklist.json").read_text())
    by = {}
    for it in wl:
        by.setdefault(it["class"], []).append(it)
    return by

def brief_for(cls, items, target, run_dir, memoria=False):
    tpl = (EXPERTS_DIR / f"{cls}.md").read_text()
    tpl = re.sub(r'^---\n.*?\n---\n', '', tpl, count=1, flags=re.S)  # drop frontmatter (claude -p chokes on leading ---)
    lines = []
    for it in items:
        lines.append(f"- {it['endpoint']}  params={it.get('params',[])}  role={it.get('role','?')}  "
                     f"goal={it.get('goal')}  plan={it.get('plan','(none)')}\n    hyp: {it.get('hypothesis','')}")
    wl_block = "\n".join(lines) if lines else "(no items for this class in this run)"
    brief = tpl.replace("{{WORKLIST}}", wl_block).replace("${T}", target).replace("$T ", f"{target} ")
    if memoria and _memoria_hints is not None:
        try:
            h = _memoria_hints(cls, items, target)
            if h:
                brief += "\n" + h
        except Exception:
            pass
    return brief

# ------------------------------------------------------------------ plan (DRY) / run
def _enabled(reg):
    return [c for c in CLASSES if reg["experts"].get(c, {}).get("enabled")]

def cmd_plan(a):
    reg = load(); m = reg["_master"]; lvl = m.get("level", 0)
    by = worklist_by_class(a.run_dir)
    seam = json.loads((Path(a.run_dir) / "seam.json").read_text())
    print(f"● DRY PLAN  (level L{lvl}, master {'ARMED' if m.get('armed') else 'DISARMED'}, memoria {'ON' if m.get('memoria') else 'off'}, risk {m.get('risk','safe')})  target {seam['target']}")
    if lvl < 2:
        print(f"  L{lvl}: {LEVELS[lvl][4]}")
        print("  → expert lane does NOT run at this level. (L0 = map only; L1 = recipe lane via `cockpit recipe`.)")
    enabled = _enabled(reg)
    tot_items = tot_min = 0
    for cls in CLASSES:
        items = by.get(cls, [])
        on = cls in enabled
        mins = reg["experts"][cls].get("minutes", 0) if on else 0
        if on:
            tot_items += len(items); tot_min += mins
        flag = "RUN " if on and lvl >= 2 else "skip"
        print(f"    [{flag}] {cls:22} {len(items):3d} worklist item(s)" + (f"  ~{mins}m" if on else ""))
    print(f"  → would dispatch {len(enabled) if lvl>=2 else 0} experts over {tot_items} items, ~{tot_min} min wall-clock budget.")
    print("  (DRY — nothing ran, 0 spend.)  Arm + level>=2 + `dispatch run` to execute.")

def cmd_run(a):
    reg = load(); m = reg["_master"]; lvl = m.get("level", 0)
    if not m.get("armed"):
        print("✋ REFUSED: master DISARMED. `dispatch arm` first (safety so nothing spends by accident).", file=sys.stderr); sys.exit(4)
    if lvl < 2:
        print(f"✋ REFUSED: level L{lvl} has no expert lane. `dispatch level 2` (or 3), or use the recipe lane.", file=sys.stderr); sys.exit(4)
    if not shutil.which("claude"):
        print("✋ no `claude` CLI on PATH — cannot launch experts.", file=sys.stderr); sys.exit(5)
    run_dir = str(Path(a.run_dir).resolve())
    seam = json.loads((Path(run_dir) / "seam.json").read_text())
    target = seam["target"]
    by = worklist_by_class(run_dir)
    enabled = _enabled(reg)
    est = sum(reg["experts"][c].get("minutes", 0) for c in enabled)
    cap = m.get("total_minutes_cap", 120)
    print(f"● DISPATCH  L{lvl}  target {target}  experts={enabled}  est ~{est}m (cap {cap}m)")
    def score():
        try:
            out = subprocess.run(["curl", "-s", "--max-time", "8", f"{target}/api/Challenges/"],
                                 capture_output=True, text=True, timeout=12).stdout
            d = json.loads(out).get("data", [])
            return sum(1 for c in d if c.get("solved"))
        except Exception:
            return None
    base = score()
    print(f"  scoreboard baseline: {base}")
    edir = Path(run_dir) / "experts"; edir.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["BS2_SEAM_RUN"] = run_dir
    env["PATH"] = f"{GB}:" + env.get("PATH", "")
    env["BS2_RISK"] = m.get("risk", "safe")
    os.environ["BS2_RISK"] = m.get("risk", "safe")   # reflex loop reads this
    spent = 0
    sysprompt = ("You are a GOVERNED per-class pentest specialist. Every target-touching command MUST go "
                 "through the 'gexec' shim (never raw curl/nmap). Record confirmed findings via "
                 "governed_seam.py finding+verify. Single authorized local target only. Do not stop until "
                 "your class's worklist is exhausted.")
    for cls in enabled:
        items = by.get(cls, [])
        if not items:
            print(f"  — {cls}: no worklist items, skipping"); continue
        mins = reg["experts"][cls].get("minutes", 8)
        if spent + mins > cap:
            print(f"  ✋ minutes cap {cap} reached — stopping before {cls} (spent ~{spent}m)"); break
        turns = reg["experts"][cls].get("max_turns", 200)
        model = reg["experts"][cls].get("model") or m.get("default_model", "claude-sonnet-5")
        brief = brief_for(cls, items, target, run_dir, memoria=bool(m.get("memoria")))
        bf = edir / f"{cls}.brief.md"; bf.write_text(brief)
        logf = edir / f"{cls}.log"
        print(f"  ▶ {cls}: {len(items)} items, {mins}m budget, model={model} → {logf.name}")
        cmd = ["timeout", f"{mins}m", "claude", "-p", "--model", model,
               "--dangerously-skip-permissions", "--max-turns", str(turns),
               "--append-system-prompt", sysprompt]
        t0 = time.time()
        with logf.open("w") as lf:
            try:
                subprocess.run(cmd, cwd=run_dir, env=env, input=brief.encode(),
                               stdout=lf, stderr=subprocess.STDOUT, timeout=mins * 60 + 30)
            except subprocess.TimeoutExpired:
                lf.write("\n[dispatch] expert hit time budget\n")
        dt = int(time.time() - t0)
        spent += max(1, dt // 60)
        now = score()
        print(f"    {cls} done in ~{dt}s   scoreboard: {now}")
    after = score()
    print(f"● DISPATCH complete. scoreboard {base} → {after}"
          + (f"  (+{after-base})" if base is not None and after is not None else ""))
    print(f"  governed status: python3 {GB}/governed_seam.py status --run-dir {run_dir}")
    subprocess.run(["python3", str(GB / "governed_seam.py"), "status", "--run-dir", run_dir])
    if lvl >= 3 and _reflex is not None:
        print("● L3 reflex loop — ground->reframe->fire autoturret cards on findings")
        try:
            _reflex.run(run_dir, max_rounds=3, fire_cards=True, redispatch=False)
        except Exception as e:
            print(f"  (reflex loop skipped: {e})")

def cmd_reflex(a):
    if _reflex is None:
        print("reflex_loop unavailable", file=sys.stderr); sys.exit(5)
    _reflex.run(a.run_dir, max_rounds=a.max_rounds, fire_cards=True, redispatch=False)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    sub.add_parser("arm").set_defaults(fn=cmd_arm)
    sub.add_parser("disarm").set_defaults(fn=cmd_disarm)
    lv = sub.add_parser("level"); lv.add_argument("n", type=int, choices=[0, 1, 2, 3]); lv.set_defaults(fn=cmd_level)
    for op in ("on", "off"):
        p = sub.add_parser(op); p.add_argument("who"); p.set_defaults(fn=cmd_toggle, op=op)
    rk = sub.add_parser("risk"); rk.add_argument("level", choices=["readonly","safe","full"]); rk.set_defaults(fn=cmd_risk)
    mem = sub.add_parser("memoria"); mem.add_argument("op", choices=["on","off"]); mem.set_defaults(fn=cmd_memoria)
    pl = sub.add_parser("plan"); pl.add_argument("--run-dir", required=True); pl.set_defaults(fn=cmd_plan)
    rn = sub.add_parser("run"); rn.add_argument("--run-dir", required=True)
    rn.add_argument("--parallel", type=int, default=1); rn.set_defaults(fn=cmd_run)
    rf = sub.add_parser("reflex"); rf.add_argument("--run-dir", required=True)
    rf.add_argument("--max-rounds", type=int, default=3); rf.set_defaults(fn=cmd_reflex)
    a = ap.parse_args()
    a.fn(a)

if __name__ == "__main__":
    main()
