"""WS-F — soundness + connectivity harness for the front-facing web operator candidates
(ariadne/corpus/candidates_web/). This is the gate that earns a candidate the right to merge:

  POSITIVE: with its specific vuln gate CONFIRMED, the operator appears in a GROUNDED plan
            for its natural goal (it chains — proves connectivity into the live corpus).
  NEGATIVE: remove that one vuln gate and the operator MUST NOT ground the goal (it can't
            fire on a bare endpoint/session — proves it invents no false path).

Run: python3 -m pytest tests/test_web_candidates.py  (or: python3 tests/test_web_candidates.py)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ariadne.loader import load_operators, DEFAULT_CORPUS
from ariadne.model import Target
from ariadne.planner import Planner

_HERE = os.path.dirname(os.path.abspath(__file__))
_CWEB = os.path.join(os.path.dirname(_HERE), "ariadne", "corpus", "candidates_web")
WEB_CANDIDATES = os.path.join(_CWEB, "candidates.yaml")
JWT_CANDIDATES = os.path.join(_CWEB, "jwt_regated.yaml")


def _all_ops():
    return (load_operators(DEFAULT_CORPUS) + load_operators(WEB_CANDIDATES)
            + load_operators(JWT_CANDIDATES))


def _grounds_via(op_name, facts, goal):
    """True iff SOME grounded (zero-assumption) plan for `goal` uses operator `op_name`."""
    ops = _all_ops()
    t = Target(name="web-test", facts=[tuple(f) for f in facts], negatives=[], goal=tuple(goal))
    sols = Planner(t, ops).plan(top_k=8)
    for s in sols:
        if not s.assumptions and any(o.name == op_name for o in s.ops):
            return True
    return False


# (op, full-confirmed facts, natural goal, the ONE vuln gate to drop for the negative case)
CASES = [
    ("bola-object-read",
     [["endpoint", "/api/orders"], ["object_ref_param", "/api/orders"],
      ["missing_object_authz", "/api/orders"], ["session", "attacker", "user"]],
     ["db_read", "/api/orders"], ["missing_object_authz", "/api/orders"]),

    ("bfla-privileged-call",
     [["endpoint", "/admin/promote"], ["privileged_function", "/admin/promote", "admin"],
      ["missing_function_authz", "/admin/promote"], ["session", "attacker", "user"]],
     ["session", "attacker", "admin"], ["missing_function_authz", "/admin/promote"]),

    # BOPLA/mass-assignment intentionally omitted — already covered by live mass-assignment-privesc.

    ("ssrf-cloud-metadata-creds",
     [["endpoint", "/fetch"], ["fetches_user_url", "/fetch"],
      ["cloud_metadata_reachable", "/fetch"]],
     ["have_cred", "cloud_iam_role"], ["cloud_metadata_reachable", "/fetch"]),

    ("xss-session-theft",
     [["endpoint", "/comments"], ["reflects_to_role", "/comments", "admin"],
      ["js_executes", "/comments"]],
     ["session", "attacker", "admin"], ["js_executes", "/comments"]),

    ("sensitive-data-exposure-cred",
     [["endpoint", "/.git/config"], ["exposes_secret", "/.git/config"]],
     ["have_cred", "/.git/config"], ["exposes_secret", "/.git/config"]),

    ("default-credentials-login",
     [["endpoint", "/manager"], ["default_creds", "/manager", "admin"]],
     ["session", "attacker", "admin"], ["default_creds", "/manager", "admin"]),

    ("host-header-reset-poison",
     [["reset_flow"], ["host_header_reflected", "/reset"], ["account", "victim", "user"]],
     ["have_cred", "victim"], ["host_header_reflected", "/reset"]),

    # re-gated JWT class (from WS-D distill, hand-tightened — jwt_regated.yaml)
    ("jwt-alg-none-forge",
     [["tool", "/login", "admin"], ["jwt_alg_none_allowed", "/login"]],
     ["session", "attacker", "admin"], ["jwt_alg_none_allowed", "/login"]),

    ("jwt-alg-confusion-rs-to-hs",
     [["tool", "/api", "admin"], ["jwt_alg_confusable", "/api"], ["have_cred", "pubkey"]],
     ["session", "attacker", "admin"], ["have_cred", "pubkey"]),

    ("jwt-forge-with-key",
     [["tool", "/api", "admin"], ["have_cred", "sk"], ["jwt_key_trusted", "/api", "sk"]],
     ["session", "attacker", "admin"], ["jwt_key_trusted", "/api", "sk"]),
]


def test_positive_each_operator_grounds_a_real_plan():
    """Each web operator, fully gated, appears in a grounded plan for its goal (it chains)."""
    for op, facts, goal, _gate in CASES:
        assert _grounds_via(op, facts, goal), f"{op}: did not ground {goal} — broken/does not chain"


def test_negative_no_operator_fires_without_its_gate():
    """Drop the one vuln gate and the operator MUST NOT ground the goal (no false path)."""
    for op, facts, goal, gate in CASES:
        pruned = [f for f in facts if list(f) != list(gate)]
        assert not _grounds_via(op, pruned, goal), \
            f"{op}: FALSE PATH — grounded {goal} without its gate {gate}. Reject/re-gate."


if __name__ == "__main__":
    fails = 0
    for name, fn in [("positive/chains", test_positive_each_operator_grounds_a_real_plan),
                     ("negative/no-false-path", test_negative_no_operator_fires_without_its_gate)]:
        try:
            fn(); print(f"PASS  {name}")
        except AssertionError as e:
            fails += 1; print(f"FAIL  {name}: {e}")
    # per-operator detail
    print("\nper-operator:")
    for op, facts, goal, gate in CASES:
        pos = _grounds_via(op, facts, goal)
        neg = _grounds_via(op, [f for f in facts if list(f) != list(gate)], goal)
        print(f"  {op:34s} chains={'Y' if pos else 'N'}  fires-without-gate={'Y!!' if neg else 'n'}")
    sys.exit(1 if fails else 0)
