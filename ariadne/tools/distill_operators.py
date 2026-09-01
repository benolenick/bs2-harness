#!/usr/bin/env python3
"""Distill a directory of technique writeups into candidate operators for review.

    python3 tools/distill_operators.py data/patt_src --out ariadne/corpus/candidates

Writes candidates.yaml + new_predicates.yaml + prints a per-file report. Nothing is
merged into the live corpus automatically — a human reviews candidates.yaml and moves
the sound ones into ariadne/corpus/operators.yaml (and blesses new_predicates.yaml
into predicates.yaml).
"""
import os
import sys
import glob
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ariadne.distill import distill   # noqa: E402

C = {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m", "d": "\033[2m", "x": "\033[0m", "b": "\033[1m"}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "data/patt_src"
    out = "ariadne/corpus/candidates"
    if "--out" in sys.argv:
        out = sys.argv[sys.argv.index("--out") + 1]
    os.makedirs(out, exist_ok=True)

    files = sorted(glob.glob(os.path.join(src, "*.txt")))
    all_ops, all_new, all_rej = [], {}, []
    for path in files:
        base = os.path.basename(path).replace(".md.txt", "").replace("__README", "")
        try:
            with open(path, errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        try:
            res = distill(text, source=base)
        except Exception as e:
            print(f"{C['r']}FAIL{C['x']} {base}: {e}")
            continue
        ops, rej = res["operators"], res["rejected"]
        for np in res["new_predicates"]:
            all_new[np["name"]] = np
        all_ops += ops
        all_rej += rej
        okc = f"{C['g']}{len(ops)} ok{C['x']}" if ops else f"{C['d']}0 ok{C['x']}"
        island = sum(1 for o in ops if not o["connects"])
        isl = f" {C['y']}({island} island){C['x']}" if island else ""
        rj = f" {C['r']}{len(rej)} rejected{C['x']}" if rej else ""
        print(f"{okc}{isl}{rj}  {C['b']}{base}{C['x']}")
        for o in ops:
            flag = f"{C['y']}~{C['x']}" if not o["connects"] else f"{C['g']}+{C['x']}"
            post = ", ".join("[" + " ".join(map(str, p)) + "]" for p in o["post"])
            print(f"    {flag} {o['name']}  ->  {post}")
        for r in rej:
            print(f"    {C['r']}x{C['x']} {r.get('name','?')}: {'; '.join(r['problems'][:2])}")

    # strip the internal 'connects'/'new_preds_used'/'warning' before writing corpus-shaped yaml
    clean = []
    for o in all_ops:
        clean.append({k: o[k] for k in ("name", "desc", "cost", "tags", "refs", "pre", "post")})
    with open(os.path.join(out, "candidates.yaml"), "w") as f:
        yaml.safe_dump({"operators": clean}, f, sort_keys=False, default_flow_style=None, width=120)
    with open(os.path.join(out, "new_predicates.yaml"), "w") as f:
        yaml.safe_dump({"predicates": list(all_new.values())}, f, sort_keys=False)

    print(f"\n{C['b']}TOTAL{C['x']}: {C['g']}{len(all_ops)} candidate operators{C['x']}, "
          f"{len(all_new)} new predicates, {C['r']}{len(all_rej)} rejected{C['x']}")
    print(f"wrote {out}/candidates.yaml + new_predicates.yaml")


if __name__ == "__main__":
    main()
