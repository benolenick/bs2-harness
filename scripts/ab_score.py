#!/usr/bin/env python3
"""ab_score.py — side-by-side A/B scorecard from normalized artifact dirs.

  usage:
    ab_score.py --a <dir>                  # one side (before the other exists)
    ab_score.py --a <dir> --b <dir>        # the A/B: table + verdict
    ab_score.py --a A --b B --json         # machine JSON

Grades the 8 auto-gradeable challenges by route overlap against the answer key;
the transcript-gradeable items print as a human checklist (per HANDOFF).
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "live"))

import ab_score as AB             # noqa: E402


def _render(res, label):
    s = res
    print(f"\n== {label} ({s['meta'].get('side')}) ==")
    for c, v in s["components"].items():
        print(f"  {c:12} {v:>6.1f}")
    print(f"  {'TOTAL':12} {s['total']:>6.1f}")
    print(f"  auto-graded: {s['matched']}/{s['key_total']} route-matched vs answer key; "
          f"findings={s['meta'].get('findings_count')} "
          f"coverage={s['meta'].get('coverage_pct'):.1f}% "
          f"projection={s['meta'].get('projection') or s['meta'].get('terminal_kind')}")
    for cid, v in sorted(s["auto"].items()):
        if v["status"] != "matched":
            print(f"    C{cid:>2}: {v['status']}")
    if s["checklist"]:
        print("  transcript-gradeable checklist (human, vs docs/challenges.md):")
        for item in s["checklist"]:
            print(f"    [ ] C{item['id']:<2} {item['title']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True)
    ap.add_argument("--b", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.b:
        cmp = AB.compare(a.a, a.b, names=("A", "B"))
        if a.json:
            print(json.dumps(cmp, indent=1))
            return
        print(f"{'side':6} {'auto':8} {'coverage':10} {'findings':9} "
              f"{'foothold':9} {'steps':6} {'terminal':22} {'total':6}")
        for row in cmp["rows"]:
            print(f"{row['side']:6} {row['auto_matched']:8} {row['coverage']:10} "
                  f"{str(row['findings']):9} {row['foothold']:9} "
                  f"{str(row['steps']):6} {row['terminal']:22} {row['total']:6}")
        _render(cmp["a"], "A")
        _render(cmp["b"], "B")
        print(f"\nVERDICT: {cmp['verdict']}")
    else:
        s = AB.score_side(a.a)
        if a.json:
            print(json.dumps(s, indent=1))
            return
        _render(s, "SINGLE")
        print(f"\nVERDICT: {s['total']:.1f}/100 (single side)")


if __name__ == "__main__":
    main()
