#!/usr/bin/env python3
"""ariadne_translate — turn autoturret's grounded engine state into a RICH, VALID Ariadne
fact-graph (WS-A of the Ariadne-starved flesh-out, gunbelt-16/17).

WHY: the old inline translate() in autoturret_planner.py emitted ~8 predicates against the
**81** in ariadne/corpus/predicates.yaml — Ariadne planned ~10% fed. This module maps the
engine's real grounded vocabulary (key=value proven facts + fingerprinted apps) across as
much of the controlled vocabulary as we can HONESTLY justify, and drops anything not in the
predicate schema so one bad fact never dead-ends /plan.

Contract (content-blind — reasons over fact KEYS + app names, never raw exploit output):
    translate_state(proven, apps, exploits_fn=None, host=None)
        -> {"facts": [[pred, ...], ...],       # valid Ariadne facts
            "dropped": [[pred, ...], ...],      # out-of-vocab, reported not used
            "provenance": {"pred(args)": "engine-fact-or-app it came from"}}

`proven` is autoturret's engine.proven: list of {"fact": "key=value", ...} (or bare strings).
`apps` is engine.apps: {app_name: version}. `exploits_fn(product)->[(product,cve)]` is
best-effort arming (defaults to a no-op so this module is unit-testable offline).

Design rules:
  * NEVER invent an action-outcome. We only emit what the engine PROVED (rce_as from a
    grounded shell, have_cred from a captured cred, crackable_hash from a captured hash).
    Speculative chaining is Ariadne's job, not ours.
  * Emit observable/context facts liberally (vuln_present, runs_as, known_exploit) — those
    are what unlock operator preconditions.
  * Validate every fact against predicates.yaml (name + arity). Invalid -> dropped[].
"""
from __future__ import annotations
import os, re, json, urllib.request, urllib.parse

_PRED_PATH = os.environ.get(
    "GB_ARIADNE_PREDS", "/home/operator/ariadne/ariadne/corpus/predicates.yaml")

# default OS user an app's web process runs as (used for runs_as + to bind rce_as targets)
DEF_USER = {"gitlab": "git", "wordpress": "www-data", "drupal": "www-data",
            "osticket": "www-data", "joomla": "www-data", "tomcat": "tomcat"}


def load_predicates(path: str = _PRED_PATH) -> dict:
    """{name: arity} from predicates.yaml. Falls back to a minimal set if unreadable so the
    translator degrades instead of dying (matches the engine's fail-soft posture)."""
    try:
        import yaml
        d = yaml.safe_load(open(path))
        return {p["name"]: int(p["arity"]) for p in d.get("predicates", [])}
    except Exception:
        return {"vuln_present": 2, "known_exploit": 2, "runs_as": 2, "rce_as": 1,
                "read_file": 1, "have_cred": 1, "cred_reused_on": 2, "crackable_hash": 1,
                "has_hash": 1, "can_read": 2, "suid_binary": 2, "can_sudo": 2, "gtfobin": 3,
                "pwn_host": 1, "controls_principal": 1, "session": 2, "file": 1}


def _safe(s) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-/]", "_", str(s))[:60]


def _valid(fact, preds: dict) -> bool:
    return bool(fact) and fact[0] in preds and preds[fact[0]] == len(fact) - 1


def _iter_proven(proven):
    """Yield (key, value) for each engine proven fact. Facts are 'key=value' strings or
    dicts {'fact': 'key=value'}; bare 'app_gitlab' style keys yield (key, '')."""
    for p in proven or []:
        f = p.get("fact") if isinstance(p, dict) else p
        if not f:
            continue
        key, _, val = str(f).partition("=")
        yield key.strip().lower(), val.strip()


def exploits_via_http(product, ariadne=None, n=3, timeout=5):
    """Best-effort /exploits arming. Returns [(product, cve_or_edb)]. Kept identical in spirit
    to the old translate so behaviour matches; used as the default exploits_fn in the loop."""
    ariadne = ariadne or os.environ.get("GB_ARIADNE", "http://127.0.0.1:8112")
    try:
        with urllib.request.urlopen(
                ariadne.rstrip("/") + "/exploits?q=" + urllib.parse.quote(product),
                timeout=timeout) as r:
            data = json.load(r)
    except Exception:
        return []
    out = []
    for m in (data.get("matches") or [])[:n]:
        cve = (m.get("cves") or [None])[0] or ("EDB-" + str(m.get("edb")))
        out.append((product, _safe(cve)))
    return out


def translate_state(proven, apps, exploits_fn=None, host=None, preds=None):
    """Engine grounded state -> rich valid Ariadne fact-graph. See module docstring."""
    preds = preds or load_predicates()
    facts, dropped, prov = [], [], {}

    def add(fact, source):
        fact = [str(fact[0])] + [_safe(x) for x in fact[1:]]
        if _valid(fact, preds):
            if fact not in facts:
                facts.append(fact)
                prov[f"{fact[0]}({','.join(map(str, fact[1:]))})"] = source
        else:
            if fact not in dropped:
                dropped.append(fact)

    # ---- app fingerprints -> vuln_present + runs_as + known_exploit -------------------
    for app, ver in (apps or {}).items():
        h = _safe(host or app)
        product = f"{_safe(app)}_{_safe(ver)}" if ver else _safe(app)
        add(["vuln_present", h, product], f"apps[{app}]={ver}")
        add(["runs_as", h, DEF_USER.get(app, "www-data")], f"apps[{app}] default web user")
        for prod, cve in (exploits_fn(app) if exploits_fn else []):
            add(["known_exploit", product, cve], f"/exploits?q={app}")

    # ---- grounded compromise facts (ONLY what the engine proved) ----------------------
    for key, val in _iter_proven(proven):
        if key == "shell" and val:                       # rce_as(<user>)
            add(["rce_as", val], f"proven shell={val}")
        elif key == "cred" and val:                      # have_cred(<cred-id>) — value scrubbed to a token
            cid = _safe(val.split(":", 1)[0]) or "cred"  # username half is a stable non-secret handle
            add(["have_cred", f"cred_{cid}"], "proven cred (captured)")
        elif key == "dc_cred" and val:
            add(["have_cred", "dc_cred"], "proven dc_cred (captured)")
        elif key in ("hash",) and val:                   # crackable_hash(<principal-or-id>)
            add(["crackable_hash", _safe(val)[:20]], "proven hash (captured)")
        elif key in ("ntlm",) and val:
            add(["has_hash", _safe(val)[:20]], "proven ntlm (captured)")
        elif key == "dc_owned" and val.lower() in ("true", "1", "yes"):
            add(["pwn_host", _safe(host or "dc")], "proven dc_owned")
            add(["controls_principal", "domain_admin"], "proven dc_owned")
        elif key.startswith("app_"):                     # bare unlocked app key -> ensure vuln_present
            app = key[4:]
            add(["vuln_present", _safe(host or app), _safe(app)], f"unlocked {key}")

    return {"facts": facts, "dropped": dropped, "provenance": prov}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="translate engine state -> Ariadne facts")
    ap.add_argument("--state", help="JSON file with {proven:[...], apps:{...}}; else a demo")
    ap.add_argument("--live-exploits", action="store_true", help="arm known_exploit via :8112")
    ap.add_argument("--host", default=None)
    a = ap.parse_args()
    if a.state:
        st = json.load(open(a.state))
    else:  # self-demo mirroring a real inlanefreight run
        st = {"apps": {"gitlab": "13.10.1", "wordpress": "5.8"},
              "proven": [{"fact": "app_gitlab"}, {"fact": "shell=git"},
                         {"fact": "cred=tom:charlie1"}, {"fact": "hash=aad3b435b51404ee"},
                         {"fact": "dc_owned=true"}]}
    exf = (lambda p: exploits_via_http(p)) if a.live_exploits else None
    res = translate_state(st.get("proven"), st.get("apps"), exploits_fn=exf, host=a.host)
    print(json.dumps(res, indent=2))
    print(f"\n# {len(res['facts'])} valid facts, {len(res['dropped'])} dropped")
