"""Recon -> facts extractor.

Turns freeform recon notes (nmap, gobuster, burp findings, an operator's prose
observations) into a validated Ariadne target fact-graph. An LLM does the messy
natural-language -> structured-tuple mapping; a deterministic validator then keeps
ONLY tuples that use a declared predicate at the right arity, and reports the rest.
The LLM proposes; the schema disposes. That keeps the output grounded even when the
model hallucinates a predicate.

LLM backend: the shared local vLLM (OpenAI-compatible) on :8000, model qwen3-14b.
No data leaves the box.
"""
from __future__ import annotations
import json
import re
import urllib.request

from .schema import vocabulary_block, load_predicates, validate_fact

VLLM_URL = "http://127.0.0.1:8000/v1/chat/completions"
MODEL = "qwen3-14b"

SYSTEM = """You are a precise information-extraction function for a penetration-test \
attack-path planner called Ariadne. You convert recon notes about ONE target system \
into structured facts, using ONLY the controlled predicate vocabulary given to you.

Rules:
- Output a SINGLE JSON object, nothing else. No prose, no markdown fences.
- Shape: {"name": str, "goal": [pred, arg...], "facts": [[pred, arg...], ...], \
"negatives": [[pred, arg...], ...], "notes": str}
- Use ONLY predicates from the vocabulary, at the exact arity shown. If a piece of \
recon does not map cleanly to a predicate, put it in "notes" instead of inventing a predicate.
- "facts" are things confirmed TRUE by recon. "negatives" are things confirmed FALSE \
(a tested-and-failed technique, a permission checked and denied) — these hard-prune \
dead branches, so only include them when the recon actually disproved something.
- Quote file paths, URLs, and anything with slashes or special characters as strings.
- Prefer specific role names: anon, user, support, admin, root. Prefer real usernames \
for OS users (www-data, webappuser, root).
- The "goal" is what the operator is trying to achieve; infer it from the notes \
(usually read_file(PATH), rce_as(USER), or session(attacker, admin))."""

FEWSHOT_USER = """RECON NOTES:
Box: acme-portal. Foothold: got a webshell as www-data via an unrestricted file upload.
Enumerating SUID: `find / -perm -4000` shows /usr/bin/find is SUID root. Goal is the
root proof file at /root/proof.txt (root-readable). Tried reading it directly as
www-data: permission denied."""

FEWSHOT_ASSISTANT = """{"name": "acme-portal", "goal": ["read_file", "/root/proof.txt"], \
"facts": [["rce_as", "www-data"], ["suid_binary", "find", "root"], \
["file", "/root/proof.txt"], ["can_read", "root", "/root/proof.txt"]], \
"negatives": [["can_read", "www-data", "/root/proof.txt"]], \
"notes": "Foothold via unrestricted upload (CWE-434). SUID find found by perm -4000 sweep."}"""


def _extract_json(text: str) -> dict:
    """Pull the first balanced JSON object out of the model's reply."""
    text = text.strip()
    # strip <think>...</think> if a reasoning model leaks it
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in model reply")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON in model reply")


def call_llm(notes: str, temperature: float = 0.0, timeout: int = 180) -> str:
    vocab = vocabulary_block()
    user = (f"VOCABULARY (predicate/arity — meaning):\n{vocab}\n\n"
            f"RECON NOTES:\n{notes.strip()}\n\n"
            "Return the JSON object now.")
    payload = {
        "model": MODEL,
        "temperature": temperature,
        "max_tokens": 2048,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": FEWSHOT_USER},
            {"role": "assistant", "content": FEWSHOT_ASSISTANT},
            {"role": "user", "content": user},
        ],
    }
    req = urllib.request.Request(
        VLLM_URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = json.load(r)
    return resp["choices"][0]["message"]["content"]


def extract(notes: str, name: str = None) -> dict:
    """Return {'target': validated-target-dict, 'rejected': [...], 'raw': str}."""
    raw = call_llm(notes)
    obj = _extract_json(raw)
    preds = load_predicates()

    def sift(items, label):
        good, bad = [], []
        for it in items or []:
            ok, why = validate_fact(it, preds)
            (good if ok else bad).append(it if ok else (it, why))
        return good, bad

    facts, bad_f = sift(obj.get("facts"), "facts")
    negs, bad_n = sift(obj.get("negatives"), "negatives")
    goal = obj.get("goal")
    goal_ok, goal_why = validate_fact(goal, preds) if goal else (False, "no goal produced")

    target = {
        "name": name or obj.get("name") or "extracted-target",
        "goal": list(goal) if goal_ok else None,
        "facts": [list(f) for f in facts],
        "negatives": [list(n) for n in negs],
        "notes": obj.get("notes", ""),
    }
    rejected = ([("fact",) + tuple([b]) for b in bad_f]
                + [("negative",) + tuple([b]) for b in bad_n])
    if not goal_ok:
        rejected.append(("goal", (goal, goal_why)))
    return {"target": target, "rejected": rejected, "raw": raw}


def to_yaml(target: dict) -> str:
    """Emit a targets/*.yaml body. Hand-rolled so tuples render as inline lists,
    matching the existing target files' style."""
    def fact_line(f):
        parts = ", ".join(_q(a) for a in f)
        return f"  - [{parts}]"

    lines = [f"# Generated by Ariadne extract from recon notes. Review before trusting.",
             f"name: {target['name']}", ""]
    if target.get("goal"):
        lines.append(f"goal: [{', '.join(_q(a) for a in target['goal'])}]")
        lines.append("")
    lines.append("facts:")
    lines += [fact_line(f) for f in target["facts"]] or ["  []"]
    lines.append("")
    lines.append("negatives:")
    lines += [fact_line(n) for n in target["negatives"]] or ["  []"]
    lines.append("")
    if target.get("notes"):
        note = target["notes"].replace("\n", " ")
        lines.append(f"notes: >")
        lines.append(f"  {note}")
    return "\n".join(lines) + "\n"


def _q(a):
    """Quote a scalar for YAML inline-list style: quote paths/URLs/special chars."""
    s = str(a)
    if s and re.fullmatch(r"[A-Za-z0-9_.-]+", s) and not s[0].isdigit():
        return s
    return '"' + s.replace('"', '\\"') + '"'
