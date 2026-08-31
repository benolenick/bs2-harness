#!/usr/bin/env python3
"""gunbelt.catalog.loader — the stable read interface for the recipe catalog.

This is the shared handle every consumer uses (reflex-arc's spray.py, the selector, the
eval harness). It parses the catalog, normalizes battle facts into a match context, and
selects the recipes whose preconditions are satisfied.

Content-blind: recipes are invocation TEMPLATES + preconditions + verify predicates. No
payloads, no stored loot, no flags. Selection is pure; it fires nothing.

CLI:
  loader.py list [--tier floor] [--phase enum] [--parallel-safe]
  loader.py select --map <map.json> [--ariadne <facts.jsonl>] [--dial semi] [--service http]
"""
import argparse, json, os, sys

DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CATALOG = os.environ.get("GB_CATALOG", os.path.join(DIR, "seed.yaml"))
_DIAL = {"manual": 0, "semi": 1, "full": 2}
_SVC_ALIAS = {"domain": "dns", "microsoft-ds": "smb", "netbios-ssn": "smb",
              "kerberos-sec": "kerberos", "ms-wbt-server": "rdp", "ldaps": "ldap",
              "http-proxy": "http", "ssl/http": "https", "www": "http"}


def alias(t):
    return _SVC_ALIAS.get(str(t).lower(), str(t).lower())


def _load_yaml(path):
    try:
        import yaml
        return yaml.safe_load(open(path)) or []
    except ImportError:
        return _mini_yaml(open(path).read())


# --- §7 quarantine: the large auto-generated decks are an AUTHORING CORPUS, not a
# production capability set. An execution engine that loads one without an explicit reviewed
# -release acknowledgement (GB_DECK_PRODUCTION=1) is downgraded to the vetted floor (seed.yaml)
# and told loudly. Consulting metadata (the CLI, authoring tools) passes consult=True and is
# unaffected. This is the single chokepoint every card-execution path funnels through.
QUARANTINED_DECKS = {"deck_run.yaml", "deck_final.yaml", "deck_final_v2.yaml"}
VETTED_FLOOR = os.path.join(DIR, "seed.yaml")


def _is_quarantined(path):
    return os.path.basename(str(path or "")) in QUARANTINED_DECKS


def load_catalog(path=None, consult=False):
    """Return the recipe list. Falls back to a tiny YAML parser if pyyaml is absent.

    consult=True  -> caller only wants metadata (list/select/authoring); load as-asked.
    consult=False -> caller may EXECUTE these cards; a quarantined deck is refused unless
                     GB_DECK_PRODUCTION=1, and the vetted floor is loaded instead."""
    chosen = path or DEFAULT_CATALOG
    if (not consult and _is_quarantined(chosen)
            and os.environ.get("GB_DECK_PRODUCTION", "0") not in ("1", "true", "yes")):
        sys.stderr.write(
            f"[catalog] QUARANTINED: {os.path.basename(str(chosen))} is an authoring corpus, "
            f"not a reviewed production deck. Refusing to hand it to an executor; loading the "
            f"vetted floor (seed.yaml) instead. Set GB_DECK_PRODUCTION=1 to override.\n")
        chosen = VETTED_FLOOR
    recipes = _load_yaml(chosen)
    for r in recipes:
        r.setdefault("tier", "standard")
        r.setdefault("autonomy", "manual")
        r.setdefault("blast_radius", "low")
        r.setdefault("parallel_safe", False)
    return recipes


# ---------- fact normalization: map.json + ariadne_facts.jsonl -> match context ----------
def _blank_ctx():
    return {"services": set(), "ports": set(), "products": set(),
            "flags": {"is_dc": False, "dc_ip": None}, "have": set(), "hosts": []}


def facts_from_map(map_path, ctx=None):
    ctx = ctx or _blank_ctx()
    m = json.loads(open(map_path).read())
    for h in m.get("hosts", []):
        hb = {"ip": h.get("ip"), "services": set(), "ports": set(), "is_dc": bool(h.get("is_dc"))}
        for p in h.get("ports", []) or []:
            if isinstance(p, dict):
                if p.get("port"): ctx["ports"].add(p["port"]); hb["ports"].add(p["port"])
                for k in ("name", "product"):
                    v = (p.get(k) or "").lower()
                    if v: ctx["services"].add(v.split()[0]); hb["services"].add(v.split()[0]); ctx["products"].add(v)
        for s in h.get("services", []) or []:
            tok = str(s).lower().split()[0]
            if tok: ctx["services"].add(tok); hb["services"].add(tok); ctx["products"].add(str(s).lower())
        # DC heuristic (recon_ingest parity): kerberos + ldap + smb on one host
        if {"kerberos", "kerberos-sec"} & hb["services"] and "ldap" in hb["services"] \
           and {"smb", "microsoft-ds", "netbios-ssn"} & hb["services"]:
            hb["is_dc"] = True
        if hb["is_dc"]:
            ctx["flags"]["is_dc"] = True; ctx["flags"]["dc_ip"] = ctx["flags"]["dc_ip"] or hb["ip"]
        ctx["hosts"].append(hb)
    # 'have' tokens from harvested creds
    for c in m.get("creds", []):
        src = (c.get("source") or "").lower()
        ctx["have"].add("userlist")
        if "phpass" in src or "hash" in src: ctx["have"].add("phpass-hashes"); ctx["have"].add("hashes")
        if "crack" in src or c.get("pass") or "password" in src: ctx["have"].add("passlist")
    ctx["services"] = {alias(x) for x in ctx["services"]}
    for h in ctx["hosts"]: h["services"] = {alias(x) for x in h["services"]}
    return ctx


def facts_from_ariadne(facts_path, ctx=None):
    ctx = ctx or _blank_ctx()
    for line in open(facts_path):
        line = line.strip()
        if not line: continue
        try: f = json.loads(line)
        except Exception: continue
        if not isinstance(f, list) or not f: continue
        pred = f[0]
        if pred == "is_dc" and len(f) > 1:
            ctx["flags"]["is_dc"] = True; ctx["flags"]["dc_ip"] = ctx["flags"]["dc_ip"] or f[1]
        elif pred == "principal": ctx["have"].add("userlist")
        elif pred == "controls_principal": ctx["have"].add("domain-creds"); ctx["have"].add("passlist")
        elif pred in ("vuln_present", "known_exploit"): ctx["have"].add("known-exploit")
        elif pred == "runs_as": ctx["have"].add("service-user")
    return ctx


# ---------- selection ----------
def _facet_ok(facet, ctx):
    (k, v), = facet.items()
    if k == "service": return str(v).lower() in ctx["services"]
    if k == "port":    return v in ctx["ports"]
    if k == "is_dc":   return bool(ctx["flags"].get("is_dc")) == bool(v)
    if k == "have":    return str(v) in ctx["have"]
    if k == "product": return any(str(v).lower() in p for p in ctx["products"])
    return False


def matches(recipe, ctx):
    return all(_facet_ok(f, ctx) for f in recipe.get("when", []))


def select(ctx, *, dial="manual", phase=None, tier=None, parallel_safe=None, service=None,
           confirms=None, catalog=None):
    """Return matching recipes, each annotated with fire disposition for the given dial."""
    cat = catalog if catalog is not None else load_catalog(consult=True)
    dlevel = _DIAL.get(dial, 0)
    out = []
    for r in cat:
        if phase and r.get("phase") != phase: continue
        if tier and r.get("tier") != tier: continue
        if parallel_safe is not None and bool(r.get("parallel_safe")) != parallel_safe: continue
        if service and not any(f.get("service") == service for f in r.get("when", [])): continue
        if confirms and confirms not in (r.get("confirms") or []): continue
        if not matches(r, ctx): continue
        floor = r.get("tier") == "floor"
        gated = r.get("blast_radius") == "high"
        auton = r.get("autonomy", "manual")
        # manual = always human-confirm (never auto), even at full dial.
        # floor safe-wins auto-fire from semi up. Otherwise dial must reach the recipe's autonomy.
        autofire = (not gated) and (
            (floor and dlevel >= 1) or
            (auton != "manual" and dlevel >= _DIAL.get(auton, 2)))
        out.append({**r, "_disposition": {
            "would_autofire": bool(autofire),
            "needs_gate": bool(gated) or not autofire,
            "floor": floor}})
    # floor first, then by phase order, then id
    order = {p: i for i, p in enumerate(
        ["recon", "enum", "exploit", "cred", "privesc", "lateral", "loot", "persist"])}
    out.sort(key=lambda r: (not r["_disposition"]["floor"], order.get(r.get("phase"), 99), r["id"]))
    return out


def recipes_confirming(fact, ctx, **kw):
    """LANE SPAWN hook: recipes whose preconditions hold AND that confirm `fact`.
    `fact` is an Ariadne predicate string (e.g. from confirm_next[].fact[0])."""
    pred = fact[0] if isinstance(fact, (list, tuple)) and fact else fact
    return select(ctx, confirms=pred, **kw)


# ---------- tiny YAML fallback (only the subset seed.yaml uses) ----------
def _mini_yaml(text):
    raise RuntimeError("pyyaml required for full parse; install python3-yaml")


def _cli():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("list"); pl.add_argument("--tier"); pl.add_argument("--phase")
    pl.add_argument("--parallel-safe", action="store_true")
    ps = sub.add_parser("select"); ps.add_argument("--map", required=True)
    ps.add_argument("--ariadne"); ps.add_argument("--dial", default="semi")
    ps.add_argument("--service"); ps.add_argument("--parallel-safe", action="store_true")
    a = ap.parse_args()
    if a.cmd == "list":
        for r in load_catalog(consult=True):
            if a.tier and r["tier"] != a.tier: continue
            if a.phase and r["phase"] != a.phase: continue
            if a.parallel_safe and not r.get("parallel_safe"): continue
            print(f"{r['id']:22} {r['tier']:8} {r['phase']:8} pll={int(bool(r.get('parallel_safe')))} {r['tool']}")
    else:
        ctx = facts_from_map(a.map)
        if a.ariadne and os.path.exists(a.ariadne): facts_from_ariadne(a.ariadne, ctx)
        sel = select(ctx, dial=a.dial, service=a.service,
                     parallel_safe=True if a.parallel_safe else None)
        print(f"# ctx services={sorted(ctx['services'])} is_dc={ctx['flags']['is_dc']} have={sorted(ctx['have'])}")
        for r in sel:
            d = r["_disposition"]
            print(f"{r['id']:22} {r['tier']:8} fire={'AUTO' if d['would_autofire'] else 'GATE'} {r['invocation'].strip()[:70]}")


if __name__ == "__main__":
    _cli()
