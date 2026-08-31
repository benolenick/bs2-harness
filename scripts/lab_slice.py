#!/usr/bin/env python3
"""lab_slice.py — the P1-2 vertical slice driver CLI (re-audit 2026-08-25).

Thin CLI over live/bola_slice.py (the library core — ONE implementation shared with
the engine consumer in manager/run_deep_deepseek.py):

    isolated principal sessions -> governed read-only replay (differential matrix)
    -> normalized response delta -> hypothesis candidate -> skeptic brief
    -> independent confirmation (answers supplied by an operator/verifier).

Everything the slice touches is GENERIC: the engagement is described by a plan file
(endpoints, principals-as-REFS, object-id sources). The slice itself knows no app.

usage: lab_slice.py --plan <plan.json> --seam <seam-dir> [--skeptic <answers.json>]

The seam must be open for the plan's target (governed_seam.py open). Every request is
a governed work order (web.recon lane, read-only). Cookie jars are REFERENCES resolved
on the exec host — values never enter this process.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "live"))

import bola_slice as BS          # noqa: E402
import governed_runner as GR     # noqa: E402
import lab                       # noqa: E402
from observation import ObservationRecord   # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--seam", required=True, help="open governed seam run-dir")
    ap.add_argument("--skeptic", default=None, help="verifier answers JSON "
                    "{checklist_key: true/false}")
    ap.add_argument("--confirm", action="store_true",
                    help="confirm the records already in slice_findings.json "
                         "(no new requests; requires --skeptic)")
    ap.add_argument("--run-dir", default="/tmp/claude-1000/-home-om/lab-slice")
    a = ap.parse_args()
    os.environ["GB_GOVERNED"] = "1"
    os.environ["BS2_SEAM_RUN"] = a.seam
    os.makedirs(a.run_dir, exist_ok=True)
    if a.confirm:
        # observe-once discipline: confirmation runs off the COLLECTED records, no
        # new target requests (the ledger would skip re-issuing them anyway)
        if not a.skeptic:
            sys.exit("--confirm needs --skeptic answers")
        data = json.load(open(f"{a.run_dir}/slice_findings.json"))
        answers = json.load(open(a.skeptic))
        confirmed = []
        for d in data["findings"]:
            rec = lab.confirm(ObservationRecord.from_dict(d),
                              skeptic_answers=answers, allow_confirm=True)
            print(f"[slice] confirm: {rec.confirmation_status} kind={rec.kind}")
            confirmed.append(rec.to_dict())
        json.dump({"findings": confirmed},
                  open(f"{a.run_dir}/slice_findings.json", "w"), indent=1)
        print(f"[slice] confirmed {len(confirmed)} record(s)")
        return
    plan = BS.load_plan(a.plan)
    runner = GR.make_runner(timeout=30)
    answers = json.load(open(a.skeptic)) if a.skeptic else None
    result = BS.run_slice(plan, runner, ledger_dir=a.run_dir,
                          skeptic_answers=answers, plan_name=a.plan)
    for p in plan["principals"]:
        print(f"[slice] {p['principal']}: objects={result['object_ids'][p['principal']]}")
    for row in result["rows"]:
        print(row)
    for rec, brief in zip(result["findings"], result["briefs"]):
        if a.skeptic:
            print(f"[slice] confirm: {rec.confirmation_status} kind={rec.kind}")
        else:
            print("[slice] skeptic brief (give a verifier these + answers):")
            print(brief)
    json.dump({"findings": [rec.to_dict() for rec in result["findings"]]},
              open(f"{a.run_dir}/slice_findings.json", "w"), indent=1)
    print(f"[slice] done: {len(result['findings'])} finding record(s) "
          f"-> {a.run_dir}/slice_findings.json")


if __name__ == "__main__":
    main()
