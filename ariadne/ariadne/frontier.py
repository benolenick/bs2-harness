"""Recon targeting by forward reachability.

The relaxed backward search answers "what might work?" badly (blind DFS gets lost in a
big corpus). But when recon is cheap and AI-driven, that is the wrong question. The right
one is: given what we can PROVE right now, which specific OBSERVABLE facts, if confirmed,
would unlock the most progress toward the goal? That is a forward computation -- cheap,
bounded, and it emits an actionable recon checklist instead of a guess.

Pipeline:
  1. forward_closure: everything provable now (semi-naive forward chaining over facts).
  2. If the goal is in the closure -> already solved (the backward planner gives the chain).
  3. Otherwise greedily pick the observable fact that, when added and re-closed, brings the
     most new goal-relevant state -- repeat until the goal is reachable or we stall. The
     sequence is a RECON PLAN: the ordered facts to go confirm.

Observable = a predicate no operator can produce (injectable, has_tool, runs_as,
kerberoastable...). Those are the things recon establishes; action outcomes are achieved.
"""
from __future__ import annotations
from .model import unify, substitute, is_ground, is_var


def _index(facts):
    idx = {}
    # Fact sets are intentionally unordered.  Canonicalize them before building
    # the match index so equally valid bindings do not change with
    # PYTHONHASHSEED (and therefore change a persisted recon plan after restart).
    for f in sorted(facts, key=repr):
        idx.setdefault((f[0], len(f)), []).append(f)
    return idx


def match_conj(patterns, idx, subst=None):
    """Yield every substitution satisfying ALL patterns against the fact index
    (facts only -- forward_closure iterates to handle operator-derived facts)."""
    subst = {} if subst is None else subst
    if not patterns:
        yield subst
        return
    first, rest = patterns[0], patterns[1:]
    for fact in idx.get((first[0], len(first)), ()):
        s2 = unify(first, fact, subst)
        if s2 is not None:
            yield from match_conj(rest, idx, s2)


def forward_closure(facts, operators, max_iters=100):
    """All ground facts derivable from `facts` via the operators (least fixpoint)."""
    facts = set(facts)
    for _ in range(max_iters):
        idx = _index(facts)
        added = False
        for op in operators:
            if not op.pre:
                continue
            for sub in match_conj(op.pre, idx):
                for post in op.post:
                    g = substitute(post, sub)
                    if is_ground(g) and g not in facts:
                        facts.add(g)
                        added = True
        if not added:
            break
    return facts


def goal_relevant_predicates(operators, goal):
    """Predicates that could matter for the goal: backward closure over the predicate
    graph (start at the goal predicate; add the pre-predicates of any operator whose
    post-predicate is already relevant). Cheap static analysis, ignores bindings."""
    relevant = {(goal[0], len(goal))}
    for _ in range(100):
        grew = False
        for op in operators:
            if any((p[0], len(p)) in relevant for p in op.post):
                for pre in op.pre:
                    k = (pre[0], len(pre))
                    if k not in relevant:
                        relevant.add(k)
                        grew = True
        if not grew:
            break
    return relevant


def _producible(operators):
    prod = set()
    for op in operators:
        for post in op.post:
            if post:
                prod.add((post[0], len(post)))
    return prod


def candidate_facts(closure, operators, producible, relevant):
    """Observable preconditions that block a goal-relevant operator from firing.

    For each operator whose post is goal-relevant, greedily bind its preconditions
    against the closure; when an OBSERVABLE precondition cannot be matched, emit it
    (grounded by the bindings so far) as a recon candidate and assume it so we can find
    the operator's other gaps too. Returns a set of candidate patterns (may contain
    variables -> 'go find out what fills this')."""
    idx = _index(closure)
    cands = {}
    for op in operators:
        if not any((p[0], len(p)) in relevant for p in op.post):
            continue
        # try each precondition in order under a running binding; collect the missing
        # observable ones. Only pursue operators that are *partly* grounded (at least
        # one precondition already satisfiable), so we don't propose whole operators
        # out of nowhere.
        for sub in _partial_match(op.pre, idx, producible):
            missing = sub.get("__missing__", [])
            grounded_any = sub.get("__grounded__", 0)
            if missing and grounded_any:
                for m in missing:
                    cands.setdefault(m, 0)
                    cands[m] += 1
            break  # first partial binding is enough for a recon hint
    return cands


def _partial_match(patterns, idx, producible, subst=None, missing=None, grounded=0):
    """Greedy single-path partial matcher: bind what we can from facts, record
    OBSERVABLE preconditions we cannot, skip producible ones we cannot (they'd be
    achieved by other operators, not confirmed by recon)."""
    subst = {} if subst is None else dict(subst)
    missing = [] if missing is None else list(missing)
    for pat in patterns:
        p = substitute(pat, subst)
        key = (pat[0], len(pat))
        matched = False
        for fact in idx.get(key, ()):
            s2 = unify(p, fact, subst)
            if s2 is not None:
                subst = s2
                matched = True
                grounded += 1
                break
        if not matched:
            if key not in producible:
                # observable + unmet -> a recon target (grounded by what we know so far)
                missing.append(p)
            # producible-but-unmet: leave it, another operator would achieve it
    subst["__missing__"] = missing
    subst["__grounded__"] = grounded
    yield subst


def recon_plan(target, operators, knowledge=None, max_steps=12):
    """Return an ordered list of observable facts to CONFIRM next, greedily chosen to
    drive toward the goal. Empty list means the goal already grounds from known facts."""
    ops = operators
    relevant = goal_relevant_predicates(ops, target.goal)
    producible = _producible(ops)
    base = set(target.facts)  # recon works from the TARGET's own facts, not universal knowledge
    closure = forward_closure(base, ops)
    goalkey = (target.goal[0], len(target.goal))
    if any(unify(target.goal, f, {}) is not None for f in closure):
        return {"solved": True, "steps": []}

    plan = []
    facts = set(base)
    for _ in range(max_steps):
        closure = forward_closure(facts, ops)
        if any(unify(target.goal, f, {}) is not None for f in closure):
            break
        cands = candidate_facts(closure, ops, producible, relevant)
        if not cands:
            break
        # score each candidate by goal-progress: add it (ground its vars to placeholders),
        # re-close, count new goal-relevant facts; big bonus if the goal becomes reachable.
        best, best_score = None, (-1, -1)
        # Equal-scoring leads need a stable tie-breaker.  Relying on dict/set
        # insertion order made the first recon question drift across processes.
        for cand in sorted(cands, key=repr):
            probe = _groundize(cand)
            newclose = forward_closure(facts | {probe}, ops)
            solved = 1 if any(unify(target.goal, f, {}) is not None for f in newclose) else 0
            gain = sum(1 for f in newclose - closure if (f[0], len(f)) in relevant)
            score = (solved, gain + cands[cand])
            if score > best_score:
                best, best_score = cand, score
        if best is None or best_score[0] == 0 and best_score[1] <= 0:
            # no candidate makes progress; still surface them as leads
            plan.extend({"confirm": list(c), "unblocks": cands[c]}
                        for c in sorted(cands, key=repr))
            break
        plan.append({"confirm": list(best), "unblocks": cands[best]})
        facts.add(_groundize(best))
    return {"solved": False, "steps": plan}


def _groundize(pattern):
    """Replace variables with a readable placeholder so a probed fact is ground."""
    return tuple((f"<{x[1:]}?>" if is_var(x) else x) for x in pattern)
