#!/usr/bin/env python3
"""oracle_watch — render the Ariadne energy advisory for a live atrun, on demand.
Oracle-side observability for the juice smoke (WS-B proof). Reads RUN_DIR's recon.json +
ariadne_facts.jsonl + negatives.json and prints the advisory the manager is acting on:
goal ladder statuses, top recon targets (where to spend energy), and the accumulating
proof-gated negatives. Read-only, fail-soft. One-shot (call it whenever); no polling loop."""
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recon_advisor as RA

RUN = os.environ.get("AUTOTURRET_RUN", "/opt/bs2/run")


def snapshot(run=RUN):
    recon = os.path.join(run, "recon.json")
    if not os.path.exists(recon):
        return f"[oracle] no recon.json in {run} yet — run not started."
    adv = RA.advise_from_recon_json(recon)
    st = adv["stamp"]
    out = [f"[oracle] {time.strftime('%H:%M:%S')}  facts={st.get('facts_n')} "
           f"corpus={str(st.get('corpus_hash'))[:8]}"
           + (f"  ERR:{st['error']}" if st.get("error") else "")]
    out.append("  goals:  " + "  ".join(
        f"{g['goal']}={g['status']}" + (f"/{g['unblocks_n']}" if g['unblocks_n'] else "")
        for g in adv["goals"]))
    if adv["recon_next"]:
        out.append("  spend energy →")
        for r in adv["recon_next"][:5]:
            out.append(f"    confirm {r['confirm']}  (unblocks {r['unblocks_goal']}, gain {r['gain']})")
    negp = os.path.join(run, "negatives.json")
    if os.path.exists(negp):
        try:
            negs = json.load(open(negp))
            out.append(f"  negatives (proof-gated prunes): {len(negs)}")
            for n in (negs if isinstance(negs, list) else [])[:4]:
                if isinstance(n, dict):
                    out.append(f"    ⊘ {n.get('fact')}  (op={n.get('op')}, cycle={n.get('cycle')})")
        except Exception:
            pass
    return "\n".join(out)


if __name__ == "__main__":
    print(snapshot(sys.argv[1] if len(sys.argv) > 1 else RUN))
