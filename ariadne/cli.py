#!/usr/bin/env python3
"""Ariadne CLI: thread a path from what you have to what you want.

    python3 cli.py plan targets/phantomkernel.yaml
    python3 cli.py plan targets/phantomkernel.yaml --top 5 --show-dead
    python3 cli.py extract recon.txt --name acme --plan
    echo "nmap says ..." | python3 cli.py extract - --name acme
    python3 cli.py exploits "drupalgeddon"
    python3 cli.py exploits CVE-2018-7600
    python3 cli.py check          # schema/corpus self-check
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ariadne.loader import load_operators, load_target, load_knowledge   # noqa: E402
from ariadne.planner import Planner                        # noqa: E402
from ariadne.model import substitute                       # noqa: E402

C = {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
     "b": "\033[94m", "d": "\033[2m", "x": "\033[0m", "bold": "\033[1m"}


def fact_str(t):
    return f"{t[0]}(" + ", ".join(str(a) for a in t[1:]) + ")"


def render(sol, ops_by_name, subst_goal):
    n_ass = len(sol.assumptions)
    tag = f"{C['g']}0 assumptions{C['x']}" if n_ass == 0 else f"{C['y']}{n_ass} assumption(s) to verify{C['x']}"
    print(f"  {C['bold']}PATH{C['x']}  [{tag}, {len(sol.ops)} steps, cost {sum(o.cost for o in sol.ops):.0f}]")
    if not sol.ops:
        print(f"    {C['d']}(goal already satisfied by known facts){C['x']}")
    for i, op in enumerate(sol.ops, 1):
        refs = f"  {C['d']}[{'; '.join(op.refs)}]{C['x']}" if op.refs else ""
        print(f"    {C['b']}{i}.{C['x']} {C['bold']}{op.name}{C['x']} :: {op.desc}{refs}")
    if sol.assumptions:
        print(f"    {C['y']}assumptions to confirm:{C['x']}")
        for a in sol.assumptions:
            print(f"       - {fact_str(a)}")
    print()


def _read_notes(src):
    if src == "-":
        return sys.stdin.read()
    with open(src) as f:
        return f.read()


def cmd_plan(args):
    ops = load_operators(args.corpus) if args.corpus else load_operators()
    target = load_target(args.target)
    knowledge = load_knowledge()
    ops_by_name = {o.name: o for o in ops}

    print(f"\n{C['bold']}Ariadne{C['x']}  target={C['bold']}{target.name}{C['x']}  "
          f"goal={C['bold']}{fact_str(target.goal)}{C['x']}")
    print(f"{C['d']}{len(target.facts)} target facts, {len(knowledge)} knowledge facts, "
          f"{len(target.negatives)} confirmed-negatives, {len(ops)} operators{C['x']}\n")

    planner = Planner(target, ops, knowledge=knowledge, max_depth=args.depth, beam=args.beam)
    plans = planner.plan(top_k=args.top)

    if planner.budget_hit:
        print(f"{C['y']}note: search hit its expansion budget ({planner.budget}) — nothing grounded, "
              f"so the relaxed results below may be incomplete. Add facts/negatives to constrain it.{C['x']}\n")
    if not plans:
        print(f"{C['r']}No path found.{C['x']}\n")
    else:
        grounded = [p for p in plans if not p.assumptions]
        print(f"{C['bold']}Ranked paths (best first):{C['x']}  "
              f"{C['g']}{len(grounded)} fully-grounded{C['x']}\n")
        for sol in plans:
            render(sol, ops_by_name, target.goal)

    if getattr(args, "show_dead", False):
        dead = [(name, why) for name, why in planner.diagnose() if why]
        if dead:
            print(f"{C['bold']}Dead branches (hit a confirmed-negative):{C['x']}")
            for name, why in dead:
                print(f"  {C['r']}x{C['x']} {name}: blocked by {', '.join(fact_str(w) for w in why)}")
            print()


def cmd_extract(args):
    from ariadne.extract import extract, to_yaml
    notes = _read_notes(args.source)
    print(f"{C['d']}extracting facts via local LLM (qwen3-14b @ :8000)...{C['x']}", file=sys.stderr)
    res = extract(notes, name=args.name)
    tgt = res["target"]
    yaml_text = to_yaml(tgt)
    print(yaml_text)
    if res["rejected"]:
        print(f"{C['y']}rejected {len(res['rejected'])} item(s) (unknown predicate/arity — "
              f"not used):{C['x']}", file=sys.stderr)
        for kind, payload in res["rejected"]:
            print(f"  {C['y']}-{C['x']} {kind}: {payload}", file=sys.stderr)
    if args.out:
        with open(args.out, "w") as f:
            f.write(yaml_text)
        print(f"{C['g']}wrote {args.out}{C['x']}", file=sys.stderr)
    if args.plan:
        if not tgt.get("goal"):
            print(f"{C['r']}no valid goal extracted — cannot plan.{C['x']}", file=sys.stderr)
            return
        from ariadne.model import Target
        from ariadne.loader import _t
        ops = load_operators()
        knowledge = load_knowledge()
        target = Target(name=tgt["name"], facts=set(_t(f) for f in tgt["facts"]),
                        negatives=set(_t(n) for n in tgt["negatives"]),
                        goal=_t(tgt["goal"]), notes=tgt.get("notes", ""))
        ops_by_name = {o.name: o for o in ops}
        print(f"\n{C['bold']}Ariadne{C['x']}  target={C['bold']}{target.name}{C['x']}  "
              f"goal={C['bold']}{fact_str(target.goal)}{C['x']}\n")
        planner = Planner(target, ops, knowledge=knowledge)
        plans = planner.plan(top_k=5)
        if not plans:
            print(f"{C['r']}No path found from the extracted facts.{C['x']}\n")
            return
        grounded = [p for p in plans if not p.assumptions]
        print(f"{C['bold']}Ranked paths:{C['x']}  {C['g']}{len(grounded)} fully-grounded{C['x']}\n")
        for sol in plans:
            render(sol, ops_by_name, target.goal)


def cmd_exploits(args):
    from ariadne.exploits import search
    hits = search(args.query, limit=args.limit)
    if not hits:
        print(f"{C['r']}no exploit-db entries match '{args.query}'.{C['x']}")
        return
    print(f"{C['bold']}Exploit-DB matches for '{args.query}':{C['x']}  ({len(hits)} shown)\n")
    for e in hits:
        cve = f"  {C['g']}{', '.join(e['cves'])}{C['x']}" if e["cves"] else ""
        loc = f"{e['platform']}/{e['type']}".strip("/")
        print(f"  {C['b']}EDB-{e['edb']}{C['x']}  {C['d']}[{loc}]{C['x']}  {e['title']}{cve}")
    print()


def cmd_recon(args):
    from ariadne.frontier import recon_plan
    ops = load_operators()
    target = load_target(args.target)
    print(f"\n{C['bold']}Ariadne recon targeting{C['x']}  target={C['bold']}{target.name}{C['x']}  "
          f"goal={C['bold']}{fact_str(target.goal)}{C['x']}")
    res = recon_plan(target, ops, max_steps=args.steps)
    if res["solved"]:
        print(f"{C['g']}The goal already grounds from known facts -- run `plan` for the chain.{C['x']}\n")
        return
    steps = res["steps"]
    if not steps:
        print(f"{C['y']}No recon leads from the current facts (nothing is one observable "
              f"fact away from progress). Feed more recon.{C['x']}\n")
        return
    print(f"{C['d']}Not yet grounded. Confirm these observable facts, in order -- each is "
          f"chosen to unlock the most progress toward the goal:{C['x']}\n")
    for i, s in enumerate(steps, 1):
        print(f"  {C['b']}{i}.{C['x']} confirm {C['bold']}{fact_str(tuple(s['confirm']))}{C['x']}"
              f"   {C['d']}(unblocks {s['unblocks']} operator instance(s)){C['x']}")
    print(f"\n{C['d']}A `<x?>` argument means 'find out what fills this'. Confirm -> add as a "
          f"fact; disprove -> add as a negative; then re-plan.{C['x']}\n")


def cmd_check(args):
    from ariadne.schema import check_coverage
    ops = load_operators()
    knowledge = load_knowledge()
    print(f"{C['bold']}Ariadne self-check{C['x']}")
    print(f"  operators: {len(ops)}   knowledge facts: {len(knowledge)}")
    warns = check_coverage(ops)
    if not warns:
        print(f"  {C['g']}schema coverage: clean (every operator predicate is declared){C['x']}")
    else:
        print(f"  {C['y']}schema coverage: {len(warns)} warning(s){C['x']}")
        for w in warns:
            print(f"    {C['y']}!{C['x']} {w}")
    try:
        from ariadne.exploits import INDEX
        n = sum(1 for _ in open(INDEX))
        print(f"  {C['g']}exploit-db index: {n} entries{C['x']}")
    except OSError:
        print(f"  {C['y']}exploit-db index: missing (run the indexer){C['x']}")


def main():
    ap = argparse.ArgumentParser(description="Ariadne attack-path planner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan", help="find ranked paths to the target's goal")
    p.add_argument("target", help="path to a target YAML fact-graph")
    p.add_argument("--corpus", default=None, help="operator corpus YAML")
    p.add_argument("--top", type=int, default=5)
    p.add_argument("--depth", type=int, default=18)
    p.add_argument("--beam", type=int, default=24)
    p.add_argument("--show-dead", action="store_true", help="report branches killed by confirmed-negatives")
    p.set_defaults(func=cmd_plan)

    e = sub.add_parser("extract", help="LLM-convert recon notes into a target fact-graph")
    e.add_argument("source", help="recon notes file, or '-' for stdin")
    e.add_argument("--name", default=None, help="target name")
    e.add_argument("--out", default=None, help="write the target YAML to this path")
    e.add_argument("--plan", action="store_true", help="immediately plan from the extracted facts")
    e.set_defaults(func=cmd_extract)

    x = sub.add_parser("exploits", help="search the Exploit-DB index by keyword or CVE")
    x.add_argument("query")
    x.add_argument("--limit", type=int, default=25)
    x.set_defaults(func=cmd_exploits)

    r = sub.add_parser("recon", help="from current facts, list the observable facts to confirm next (recon targeting)")
    r.add_argument("target", help="path to a target YAML fact-graph")
    r.add_argument("--steps", type=int, default=12)
    r.set_defaults(func=cmd_recon)

    c = sub.add_parser("check", help="schema/corpus/index self-check")
    c.set_defaults(func=cmd_check)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
