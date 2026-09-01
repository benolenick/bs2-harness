"""Distill prose technique writeups into candidate Ariadne OPERATORS.

Harder than fact extraction: an operator is a reusable edge (pre -> post), and a
BAD operator invents false attack paths. So this stages CANDIDATES for review, it
does not auto-merge. Each candidate is:
  - schema-validated (every predicate declared at the right arity; the writeup may
    propose NEW predicates, which are collected separately for a human to bless),
  - checked for non-empty pre AND post,
  - checked for CONNECTIVITY: does it share a predicate with the existing corpus so
    it can actually chain into a plan? Islands are flagged, not merged.

LLM: local vLLM (:8000, qwen3-14b). Nothing leaves the box.
"""
from __future__ import annotations
import json
import re
import urllib.request

from .schema import vocabulary_block, load_predicates, validate_pattern, Predicate
from .loader import load_operators
from .extract import VLLM_URL, MODEL, _extract_json

SYSTEM = """You distill ONE penetration-testing technique writeup into reusable \
attack-path OPERATORS for a planner called Ariadne.

An OPERATOR is a rule: IF its preconditions hold, THEN its postconditions become \
true. It is target-independent: use VARIABLES (strings starting with ?) for anything \
specific (?u for a user, ?e for an endpoint, ?t for a tool, ?file for a file).

Output a SINGLE JSON object, no prose, no markdown fences:
{
  "operators": [
    {"name": "kebab-case-name", "desc": "one sentence", "cost": 2,
     "tags": ["web","rce"], "refs": ["CWE-78 ..."],
     "pre":  [["predicate","?var","literal"], ...],
     "post": [["predicate","?var"], ...]}
  ],
  "new_predicates": [{"name":"...","arity":N,"means":"..."}]
}

HARD RULES:
- REUSE the given vocabulary predicates whenever possible — that is how your operator \
chains into real plans. Only introduce a new predicate when nothing fits, and then you \
MUST declare it in "new_predicates" with its arity and meaning.
- Every operator needs a NON-EMPTY pre AND a NON-EMPTY post.
- Prefer operators whose POST is a plannable outcome the planner cares about: \
rce_as(?u), read_file(?file), db_read(?t), session(attacker, ROLE) — or a new \
capability predicate that a further operator could consume.
- Model the ENABLING CONDITIONS as pre (an endpoint exists, input is reflected, a \
parser is misconfigured, a process runs as a user). Do NOT model payload syntax.
- cost 1 (trivial) .. 4 (heavy/fragile). Add CWE ids to refs when the class has one.
- 1 to 3 operators per writeup. Quality over quantity. If the writeup is not an \
exploitation primitive (e.g. pure recon), return an empty operators list."""

EXAMPLE_OPS = """EXISTING OPERATORS (match this style; these predicates already chain):
- ssti-rce:  pre [renders_user_input ?e][template_engine ?e jinja][runs_as ?e ?u] -> post [rce_as ?u]
- command-injection-rce: pre [tool ?t ?role][session attacker ?role][shell_interpolates ?t ?u] -> post [rce_as ?u]
- lfi-path-traversal: pre [endpoint ?e][serves_file_by_param ?e][no_path_canonicalization ?e][runs_as ?e ?u][can_read ?u ?file] -> post [read_file ?file]
- sqli-open-channel: pre [tool ?t ?role][session attacker ?role][db_backed ?t][injectable ?t] -> post [db_read ?t]
- os-rce-file-read: pre [rce_as ?u][can_read ?u ?file] -> post [read_file ?file]"""


def _corpus_predicates(operators) -> set:
    s = set()
    for op in operators:
        for pat in list(op.pre) + list(op.post):
            if pat:
                s.add(pat[0])
    return s


def call_llm(writeup: str, timeout: int = 240) -> str:
    vocab = vocabulary_block()
    user = (f"VOCABULARY (predicate/arity — meaning):\n{vocab}\n\n{EXAMPLE_OPS}\n\n"
            f"TECHNIQUE WRITEUP:\n{writeup[:12000]}\n\nReturn the JSON object now.")
    payload = {
        "model": MODEL, "temperature": 0.0, "max_tokens": 3000,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": user}],
    }
    req = urllib.request.Request(VLLM_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)["choices"][0]["message"]["content"]


def distill(writeup: str, source: str = "") -> dict:
    """Return {'operators': [...ok...], 'new_predicates': [...], 'rejected': [...], 'raw': str}."""
    raw = call_llm(writeup)
    obj = _extract_json(raw)
    declared = load_predicates()
    existing_ops = load_operators()
    existing_names = {o.name for o in existing_ops}
    corpus_preds = _corpus_predicates(existing_ops)

    # provisional predicates the model proposes -> add to a working set for validation
    proposed = {}
    for np in obj.get("new_predicates", []) or []:
        try:
            proposed[np["name"]] = Predicate(np["name"], int(np["arity"]), np.get("means", ""), None)
        except (KeyError, ValueError, TypeError):
            pass
    working = dict(declared)
    working.update(proposed)

    good, rejected = [], []
    for op in obj.get("operators", []) or []:
        name = op.get("name", "").strip()
        pre = op.get("pre") or []
        post = op.get("post") or []
        problems = []
        if not name:
            problems.append("missing name")
        if name in existing_names:
            problems.append(f"duplicate of existing operator '{name}'")
        if not pre:
            problems.append("empty preconditions")
        if not post:
            problems.append("empty postconditions")
        for pat in pre + post:
            ok, why = validate_pattern(pat, working)
            if not ok:
                problems.append(f"{pat}: {why}")
        # connectivity: does any predicate touch the existing corpus?
        op_preds = {p[0] for p in (pre + post) if p}
        connects = bool(op_preds & corpus_preds)
        rec = {"name": name, "desc": op.get("desc", ""), "cost": op.get("cost", 2),
               "tags": op.get("tags", []), "refs": op.get("refs", []),
               "pre": pre, "post": post, "source": source,
               "connects": connects,
               "new_preds_used": sorted(op_preds & set(proposed))}
        if problems:
            rejected.append({**rec, "problems": problems})
        else:
            if not connects:
                rec["warning"] = "island: shares no predicate with the existing corpus"
            good.append(rec)

    used_new = set()
    for op in good:
        used_new.update(op["new_preds_used"])
    new_preds = [{"name": n, "arity": proposed[n].arity, "means": proposed[n].means}
                 for n in sorted(used_new)]
    return {"operators": good, "new_predicates": new_preds, "rejected": rejected, "raw": raw}
