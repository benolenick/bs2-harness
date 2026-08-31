#!/usr/bin/env python3
"""gunbelt.authoring.gate — the hard gate every auto-authored recipe must survive
before it can enter the review queue (and later, be fired).

Checks, in order:
  1. shape       — required fields present, enums legal
  2. vocab join  — operator: is a known Ariadne operator (or flagged NEW);
                   confirms:/emits: tokens are known Ariadne predicates (the 500-guard)
  3. content-blind — invocation is a template, not an embedded payload/loot/flag
  4. two-channel  — verify.success_if exists and is non-trivial
Returns a verdict; the driver routes PASS -> review queue, else -> rejected.jsonl.
Dedup is a separate pure key so N chunks describing one move collapse to one card.
"""
from __future__ import annotations
import re, json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vocab

def _predname(tok):
    # 'session/2' -> 'session';  'read_file /root' -> 'read_file'
    return re.split(r'[/\s]', str(tok).strip())[0] if tok else tok


PARAM_VOCAB = {
    "host","port","url","scheme","domain","zone","vhost",
    "wordlist","userlist","passlist","namelist","resolver_list","candidate_list",
    "user","password","hash","token","key",
    "product","version","module","cve","edb",
    "lhost","lport",
    "threads","timeout","rate","depth","output","report",
    "status_codes","filtered_codes","min_cvss","wait","timing","aggression","sender","recipient",
}


TIERS = {"floor", "standard", "heavy"}
AUTON = {"manual", "semi", "full"}
BLAST = {"none", "low", "high"}
PHASES = {"recon", "enum", "exploit", "cred", "privesc", "lateral", "loot", "persist"}
REQUIRED = ("id", "name", "phase", "tier", "autonomy", "when", "tool", "invocation", "verify")

# content-blindness red flags: a template must not carry a concrete payload/loot/flag
_PAYLOAD_SMELLS = [
    re.compile(r"HTB\{"), re.compile(r"flag\{", re.I),
    re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),           # long base64 blob
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?!.*\{\{)"),  # hardcoded IP w/ no template var nearby
]


def _dedup_key(card: dict) -> str:
    tool = str(card.get("tool", "")).lower().strip()
    op = str(card.get("operator", "")).lower().strip()
    wkeys = sorted(k for w in (card.get("when") or []) if isinstance(w, dict) for k in w)
    return f"{tool}|{op}|{','.join(wkeys)}"


def gate(card: dict, pred_names=None, op_names=None) -> dict:
    pred_names = pred_names if pred_names is not None else vocab.predicate_names()
    op_names = op_names if op_names is not None else vocab.operator_names()
    problems, warnings = [], []

    # 1. shape
    for f in REQUIRED:
        if not card.get(f):
            problems.append(f"missing required field '{f}'")
    if card.get("tier") and card["tier"] not in TIERS:
        problems.append(f"tier '{card['tier']}' not in {sorted(TIERS)}")
    if card.get("autonomy") and card["autonomy"] not in AUTON:
        problems.append(f"autonomy '{card['autonomy']}' not in {sorted(AUTON)}")
    br = card.get("blast_radius", "low")
    if br not in BLAST:
        problems.append(f"blast_radius '{br}' not in {sorted(BLAST)}")
    if card.get("phase") and card["phase"] not in PHASES:
        warnings.append(f"phase '{card['phase']}' unusual (not in {sorted(PHASES)})")
    if not isinstance(card.get("when"), list) or not card.get("when"):
        problems.append("'when' must be a non-empty list of single-key dicts")

    # 2. vocab join — the 500-guard
    op = card.get("operator")
    if op and op not in op_names:
        warnings.append(f"operator '{op}' is NOT a live Ariadne operator -> needs a distilled "
                        f"operator before this recipe can join the replan loop (NEW-OP)")
    if not op:
        warnings.append("no operator: set (recipe fires but won't chain in Ariadne)")
    confirms = card.get("confirms") or []
    emits = ((card.get("verify") or {}).get("emits")) or []
    for tok in list(confirms) + list(emits):
        base = _predname(tok)
        if base and base not in pred_names:
            warnings.append(f"vocab: '{tok}' is not a live Ariadne predicate "
                            f"(fires fine, but won't feed the planner as a fact)")
    # confirms specifically is the hard 500 join
    for tok in confirms:
        base = _predname(tok)
        if base and base not in pred_names:
            problems.append(f"confirms '{tok}' OUT-OF-VOCAB -> would 500 Ariadne's replan loop")

    # 3. content-blindness
    inv = str(card.get("invocation", ""))
    for rx in _PAYLOAD_SMELLS:
        if rx.search(inv):
            # a templated IP ({{host}}) is fine; only flag concrete embedded values
            if rx.pattern.startswith("HTB") or "base64" in rx.pattern or "flag" in rx.pattern.lower():
                problems.append(f"content-blindness: invocation embeds a concrete payload/flag/loot")
            break
    if "{{" not in inv and card.get("tier") != "floor":
        warnings.append("invocation has no {{template}} vars — may be target-specific, not reusable")

    # 4. two-channel success
    v = card.get("verify") or {}
    if not v.get("success_if"):
        problems.append("verify.success_if missing (no success gate)")

    return {"id": card.get("id"), "verdict": "PASS" if not problems else "REJECT",
            "problems": problems, "warnings": warnings, "dedup_key": _dedup_key(card)}


def gate_yaml_file(path: str) -> list:
    import yaml
    cards = yaml.safe_load(open(path)) or []
    pn, on = vocab.predicate_names(), vocab.operator_names()
    return [gate(c, pn, on) for c in cards]


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else "/opt/bs2/catalog/seed.yaml"
    print(f"=== gating {tgt} against LIVE Ariadne vocab ===\n")
    for r in gate_yaml_file(tgt):
        mark = "\033[32mPASS\033[0m" if r["verdict"] == "PASS" else "\033[31mREJECT\033[0m"
        print(f"[{mark}] {r['id']}")
        for p in r["problems"]:
            print(f"    \033[31m✗ {p}\033[0m")
        for w in r["warnings"]:
            print(f"    \033[33m! {w}\033[0m")
