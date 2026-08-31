#!/usr/bin/env python3
"""ab_run.py — run ONE side of the blind reset-state A/B (HANDOFF protocol):

    crapi reset -> launch harness -> wait terminal -> collect artifacts -> answer key.

  usage:
    ab_run.py --side bs2 --steps 30                        # governed BS2 side
    ab_run.py --side mit --steps 30 --cmd 'mit-harness.sh' # friend's harness side
    ab_run.py --side bs2 --steps 30 --skip-reset           # board already fresh

The MIT side is arbitrary: --cmd runs through `bash -lc` with the launch working dir;
the protocol expects it to produce its own terminal marker or exit. For a long-running
MIT process the caller can use --cmd '...; touch DONE' and wait_terminal falls back to
process-gone detection of the bash wrapper.
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "live"))

import ab_runner as AB          # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", required=True, help="bs2|mit (a label; bs2 = governed launch)")
    ap.add_argument("--steps", type=int, default=30)
    ap.add_argument("--skip-reset", action="store_true")
    ap.add_argument("--cmd", default=None,
                    help="MIT side: the harness launch command (bash -lc)")
    ap.add_argument("--model", default=os.environ.get("TROOPER_MODEL", ""))
    ap.add_argument("--out", default=None,
                    help="artifact dir (default ab_artifacts/<side>-<unix-ts>)")
    a = ap.parse_args()
    out = a.out or f"{HERE}/ab_artifacts/{a.side}-{int(time.time())}"

    def mit_launch(_steps):
        if not a.cmd:
            sys.exit("--side mit requires --cmd")
        runbase = out + ".run"
        os.makedirs(runbase, exist_ok=True)
        log = f"{runbase}/run.log"
        with open(log, "w") as fh:
            proc = subprocess.run(["bash", "-lc", a.cmd],
                                  cwd=HERE, stdout=fh, stderr=subprocess.STDOUT)
        open(f"{runbase}/RUN.pid", "w").write(str(proc.pid))
        return runbase, log

    res = AB.run_side(a.side, a.steps, out, reset=not a.skip_reset,
                      model=a.model, launch_fn=mit_launch if a.cmd else None)
    if "error" in res:
        sys.exit(f"[ab] {a.side}: {res['error']}")
    print(f"[ab] {a.side}: artifacts -> {res['out_dir']}")
    print(f"[ab] terminal: {res['terminal']}")
    print(f"[ab] next: python3 scripts/ab_score.py --a {res['out_dir']} "
          f"(or --a ... --b ... when both sides exist)")


if __name__ == "__main__":
    main()
