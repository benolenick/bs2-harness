"""Ariadne planner: goal-directed backward chaining over technique operators.

Given a Target (facts + confirmed-negatives + goal) and a corpus of Operators,
find ranked attack PATHS from "what we have" (facts) to the goal.

Two-phase search keeps it complete and deterministic:
  1. GROUNDED phase: prove the goal using only facts + operators, NO assumptions.
     Memoised on ground subgoals, so it is fast and finds every real chain.
  2. RELAXED phase (only if nothing grounds): allow unprovable leaves as
     ASSUMPTIONS to verify, ranked by fewest assumptions. This surfaces
     near-miss paths (what you'd need to confirm to make them work).

A subgoal that matches a confirmed NEGATIVE is hard-pruned in both phases. That
is what kills dead branches automatically (e.g. "uid999 can_read the 0640 file"
was proven false, so every path through it dies instantly).

Ranking: fewest assumptions, then shortest chain, then lowest total cost.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .model import unify, substitute, is_ground, rename_pattern, Operator, Target


@dataclass
class Solution:
    ops: list = field(default_factory=list)          # operators used, leaf-first
    assumptions: list = field(default_factory=list)  # unproven subgoals (observable leaves)
    subst: dict = field(default_factory=dict)

    def vagueness(self):
        # variable-occurrences across all assumptions. An assumption naming concrete
        # entities (has_tool(sysmind, file_read)) is an ACTIONABLE recon task; one full
        # of unbound variables (can_sudo(?u, ?bin)) is "assume something somewhere" --
        # noise. Ranking on this floats concrete near-misses above generic guesses.
        from .model import is_var
        return sum(1 for a in self.assumptions for x in a if is_var(x))

    def key(self):
        return (self.vagueness(), len(self.assumptions),
                len(self.ops), sum(o.cost for o in self.ops))


class Planner:
    def __init__(self, target: Target, operators: list,
                 knowledge: set = None, max_depth: int = 20, beam: int = 64,
                 budget: int = 30000, relaxed_depth: int = 6):
        self.t = target
        self.operators = operators
        self.max_depth = max_depth
        self.relaxed_depth = relaxed_depth
        self.beam = beam
        # fact base = this target's facts + universal knowledge (e.g. GTFOBins)
        self.knowledge = knowledge or set()
        self.sorted_facts = sorted(self.t.facts | self.knowledge, key=str)
        # Index by predicate name + arity so a goal only touches RELEVANT facts and
        # operators. Without this every goal linearly scanned all ~1900 knowledge
        # facts and all operators -- fine at 19 operators, quadratic death at 39 on a
        # deep AD graph. Facts/operators keyed on the head predicate collapse that.
        self.facts_by_pred = {}
        for f in self.sorted_facts:
            self.facts_by_pred.setdefault((f[0], len(f)), []).append(f)
        # Relaxed phase uses ONLY the target's own facts, not the ~1900 universal
        # knowledge facts (GTFOBins). Those are a lookup table for GROUNDING real
        # privesc; letting an unbound gtfobin(?bin,...) fan out over all of them in the
        # speculative relaxed phase just burns the budget and buries the real near-miss.
        self.target_facts_by_pred = {}
        for f in sorted(self.t.facts, key=str):
            self.target_facts_by_pred.setdefault((f[0], len(f)), []).append(f)
        self.ops_by_post = {}
        self.producible = set()
        for op in operators:
            for post in op.post:
                if post:
                    self.ops_by_post.setdefault((post[0], len(post)), []).append((op, post))
                    self.producible.add((post[0], len(post)))
        self.memo = {}
        self._counter = 0
        # Robustness against combinatorial blow-up: a hard ceiling on goal
        # expansions. When hit, remaining subgoals collapse to assumptions (or
        # dead ends in the grounded phase) instead of hanging. The relaxed phase
        # (which lets suid_binary/gtfobin leaves be *assumed*, fanning out over the
        # whole knowledge base) is what needs this most, so it also runs shallower.
        self.budget = budget
        self._nodes = 0
        self.budget_hit = False

    def _is_negated(self, goal, subst) -> bool:
        g = substitute(goal, subst)
        return any(unify(g, neg, subst) is not None for neg in self.t.negatives)

    # ---- solve a single goal -------------------------------------------
    def solve_goal(self, goal, subst, depth, stack, allow_assume) -> list:
        if self._is_negated(goal, subst):
            return []
        g = substitute(goal, subst)
        # An ASSUMPTION is only legitimate for an OBSERVABLE predicate -- one no
        # operator can produce (injectable, has_tool, runs_as, kerberoastable...).
        # Action OUTCOMES (read_file, rce_as, controls_principal, member_of...) are
        # producible, so they must be ACHIEVED by an operator chain, never assumed.
        # This is what stops the relaxed phase from "solving" a goal by assuming the
        # goal itself, or short-circuiting real work by assuming an intermediate win.
        assumable = allow_assume and (goal[0], len(goal)) not in self.producible
        if g in stack or depth > self.max_depth:
            return [Solution([], [g], subst)] if assumable else []
        self._nodes += 1
        if self._nodes > self.budget:
            self.budget_hit = True
            return [Solution([], [g], subst)] if assumable else []

        ground = is_ground(g)
        memo_key = (g, allow_assume)
        if ground and memo_key in self.memo:
            return [Solution(list(o), list(a), subst) for (o, a) in self.memo[memo_key]]

        key = (goal[0], len(goal))
        facts_index = self.target_facts_by_pred if allow_assume else self.facts_by_pred
        sols = []
        # (a) satisfied by a known fact (only facts with the same predicate+arity)
        for fact in facts_index.get(key, ()):
            s2 = unify(goal, fact, subst)
            if s2 is not None:
                sols.append(Solution([], [], s2))
        # (b) produced by an operator whose post matches this predicate -- standardize
        #     apart with fresh variables so reused/nested operators don't collide
        for op, post in self.ops_by_post.get(key, ()):
            self._counter += 1
            n = self._counter
            post_rn = rename_pattern(post, n)
            s2 = unify(goal, post_rn, subst)
            if s2 is None:
                continue
            pre_r = [rename_pattern(p, n) for p in op.pre]
            for cs in self.solve_conj(pre_r, s2, depth + 1, stack + (g,), allow_assume):
                # NB: do NOT ban an operator that already appears in cs.ops -- real
                # paths reuse the same edge (ad-group-inherit, ad-pth, ad-admin-to-pwn
                # fire many times in one AD chain). Loop safety is the `stack` ground-
                # goal check + depth + budget, not operator-set uniqueness.
                sols.append(Solution(cs.ops + [op], cs.assumptions, cs.subst))
        # (c) leave as an assumption -- only for observable (non-producible) predicates
        if assumable:
            sols.append(Solution([], [g], subst))

        sols = self._prune(sols)
        if ground:
            self.memo[memo_key] = [(s.ops, s.assumptions) for s in sols]
        return sols

    # ---- solve a conjunction of goals ----------------------------------
    def solve_conj(self, goals, subst, depth, stack, allow_assume) -> list:
        if not goals:
            return [Solution([], [], subst)]
        first, rest = goals[0], goals[1:]
        out = []
        for s1 in self.solve_goal(first, subst, depth, stack, allow_assume):
            for s2 in self.solve_conj(rest, s1.subst, depth, stack, allow_assume):
                out.append(Solution(_dedup(s1.ops + s2.ops),
                                    s1.assumptions + s2.assumptions, s2.subst))
        return self._prune(out)

    def _prune(self, sols) -> list:
        # Dedup by ops + assumptions + the variable BINDINGS. Two solutions with
        # the same operators but different substitutions are genuinely different
        # (e.g. binding ?t=search_message vs newsletter_export); collapsing them
        # by ops alone silently drops valid branches.
        seen = {}
        for s in sorted(sols, key=lambda x: x.key()):
            sig = (tuple(o.name for o in s.ops),
                   tuple(sorted(map(str, s.assumptions))),
                   tuple(sorted((k, str(v)) for k, v in s.subst.items())))
            if sig not in seen:
                seen[sig] = s
        return list(seen.values())[: self.beam]

    # ---- public entry ---------------------------------------------------
    def plan(self, top_k: int = 5) -> list:
        self.memo = {}
        self._nodes = 0
        self.budget_hit = False
        grounded = self.solve_goal(self.t.goal, {}, 0, (), allow_assume=False)
        grounded = [s for s in grounded if not s.assumptions]
        if grounded:
            grounded = self._dominance_filter(grounded)
            grounded.sort(key=lambda s: s.key())
            return grounded[:top_k]
        # Nothing grounds -> relaxed phase. Run it shallower: assumption-laden paths
        # deeper than relaxed_depth aren't actionable and are what fan out over the
        # knowledge base. Budget still backstops it.
        self.memo = {}
        self._nodes = 0
        saved = self.max_depth
        self.max_depth = min(self.max_depth, self.relaxed_depth)
        try:
            relaxed = self.solve_goal(self.t.goal, {}, 0, (), allow_assume=True)
        finally:
            self.max_depth = saved
        relaxed = self._dominance_filter(relaxed)
        relaxed.sort(key=lambda s: s.key())
        return relaxed[:top_k]

    def _dominance_filter(self, sols) -> list:
        """Drop any path that does strictly more work than another for no benefit:
        if solution A's operator-set is a proper superset of B's AND A has no fewer
        assumptions, A is redundant (it detoured through extra techniques that B
        didn't need). This is what removes 'escalate-to-root THEN use a root SUID to
        read as root' when a direct read already exists. Distinct alternatives with
        incomparable op-sets are all kept."""
        opsets = [(set(o.name for o in s.ops), len(s.assumptions), s) for s in sols]
        keep = []
        for aset, aass, s in opsets:
            dominated = False
            for bset, bass, other in opsets:
                if other is s:
                    continue
                if bset < aset and bass <= aass:   # B is a proper subset, no worse
                    dominated = True
                    break
            if not dominated:
                keep.append(s)
        return keep

    def diagnose(self) -> list:
        """For each operator that could directly produce the goal, report which
        preconditions are provably DEAD: a precondition that, once the goal binds
        its variables, is GROUND and equals a confirmed-negative. We require it to
        be ground so we don't slander a live operator whose unbound precondition
        (e.g. can_read(?u, FILE)) merely *could* unify with a negative for some ?u
        the operator would never actually pick. This is a shallow first-look aid,
        not the planner: branches that die only through deep reasoning aren't flagged."""
        from .model import is_ground
        out = []
        for op in self.operators:
            for post in op.post:
                s = unify(self.t.goal, post, {})
                if s is None:
                    continue
                dead = []
                for p in op.pre:
                    pg = substitute(p, s)
                    if not is_ground(pg):
                        continue
                    if any(unify(pg, neg, {}) is not None for neg in self.t.negatives):
                        dead.append(pg)
                if dead:
                    out.append((op.name, dead))
        return out


def _dedup(ops):
    out = []
    for o in ops:
        if o not in out:
            out.append(o)
    return out
