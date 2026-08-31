#!/usr/bin/env python3
"""gunbelt.authoring.author — mass-produce GENERIC, target-agnostic recipe cards for a
category, snap them to the live Ariadne vocab, gate them, write a review queue.

Doctrine (Ben, 2026-08-22): cards are NOT aimed at a box's known answer. They are generic
moves against a SERVICE CLASS. Coverage-by-volume: author so many that one happens to fit.
The engine never sees the target's solution — only a family name + the legal vocab.

Backend: codex exec, read-only, -o (final message only). Model chosen by caller.
"""
from __future__ import annotations
import sys, os, json, subprocess, re, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vocab, gate

CODEX = "/home/operator/.local/bin/codex"
MODEL_ARGS = ["-m", "gpt-5.6-luna"]   # spark too weak for schema (19% yield); luna = fast+affordable+follows schema

SCHEMA_HINT = """A recipe card is ONE firable, GENERIC move against a service class. JSON fields:
  id (kebab), name, phase (recon|enum|exploit|cred|privesc|lateral|loot|persist),
  tier (floor=free/unskippable | standard | heavy), autonomy (manual|semi|full),
  when: [ {service: ftp}, {port: 21} ]   # preconditions matched vs recon facts
  tool: <binary>, invocation: "<cmd with {{host}} {{port}} {{wordlist}} {{user}} templates>",
  parallel_safe: bool, blast_radius (none|low|high),
  operator: <reuse a live Ariadne operator name, or "" if none fits>,
  confirms: [<live Ariadne PREDICATE names only>],
  verify: { success_if: "<check over stdout/exit>", emits: [<predicate names>] },
  cost_hint (cheap|moderate|slow), notes: "<one line opsec>"
"""

RULES = """HARD RULES:
- GENERIC ONLY. Never reference a specific host, flag, filename, or known answer. Use {{templates}}.
- Content-blind: invocation is a TOOL INVOCATION template, never an embedded payload/flag/loot value.
- confirms: and verify.emits MUST use ONLY predicate names from the VOCAB below (else it 500s the planner). If nothing fits, use [].
- operator: SHOULD reuse a listed Ariadne operator; if none fits, set "".
- Prefer a real success_if that proves the shot landed (two-channel: response OR out-of-band).
- Cover the FAMILY broadly: the common variants, brute/enum/exploit forms, and version->CVE 'lead' cards
  (a lead only claims 'which door, which key' — tier it 'standard', note it's a lead)."""

EXAMPLE_CARD = """A COMPLETE, well-formed card (match this EXACTLY — every field present):
{
  "id": "ftp-anon-listing",
  "name": "Anonymous FTP login and directory listing",
  "phase": "enum",
  "tier": "floor",
  "autonomy": "semi",
  "when": [{"service": "ftp"}, {"port": 21}],
  "tool": "curl",
  "invocation": "curl -s --max-time 15 ftp://anonymous:anonymous@{{host}}:{{port}}/",
  "parallel_safe": true,
  "blast_radius": "none",
  "operator": "",
  "confirms": ["session"],
  "verify": {"success_if": "exit==0 and stdout is a non-empty directory listing", "emits": ["session"]},
  "cost_hint": "cheap",
  "notes": "always try before any auth brute-force"
}"""

def build_prompt(family_desc: str, n: int) -> str:
    return (f"{SCHEMA_HINT}\n{RULES}\n\n{EXAMPLE_CARD}\n\nVOCAB (the ONLY legal predicate/operator names):\n"
            f"{vocab.llm_vocab_block()}\n\n"
            f"FAMILY TO COVER: {family_desc}\n\n"
            f"Emit {n} distinct GENERIC cards covering this family as broadly as you can. "
            f"Output ONLY a JSON array of card objects. No prose, no markdown fences.")

def _extract_json_array(text: str):
    text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M).strip()
    i, j = text.find("["), text.rfind("]")
    if i == -1 or j == -1:
        return []
    try:
        return json.loads(text[i:j+1])
    except json.JSONDecodeError:
        # salvage: object-by-object
        out = []
        for m in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text[i:j+1]):
            try: out.append(json.loads(m.group(0)))
            except json.JSONDecodeError: pass
        return out

def call_codex(prompt: str, workdir: str, timeout=600) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, dir=workdir) as f:
        out_path = f.name
    cmd = [CODEX, "exec", "-", "-s", "read-only", "--skip-git-repo-check",
           *MODEL_ARGS, "-C", workdir, "-o", out_path]
    try:
        subprocess.run(cmd, input=prompt.encode(), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass  # slow family -> skip, don't kill the batch
    try:
        return open(out_path).read() if os.path.exists(out_path) else ""
    except OSError:
        return ""

def author_family(family_desc: str, n: int, workdir: str) -> list:
    raw = call_codex(build_prompt(family_desc, n), workdir)
    return _extract_json_array(raw)

if __name__ == "__main__":
    # pilot families for the linux-service category (generic; blind to the box's answer)
    FAMILIES = {
        "ftp": "FTP (port 21): anonymous login+listing, credential brute-force, writable-dir upload-to-webroot, FTP bounce, and vsftpd version->CVE lead cards.",
        "smtp": "SMTP (port 25): user enumeration via VRFY/EXPN/RCPT, open-relay test, credential brute, Postfix version->CVE leads.",
        "dns": "DNS (port 53): AXFR zone transfer, subdomain brute-force, version.bind query, reverse-lookup sweep, DNS server version->CVE leads.",
        "pop3imap": "POP3/IMAP (110/143/993/995 Dovecot): credential brute, credential-reuse from harvested creds, authenticated mailbox read for secrets, Dovecot version->CVE leads.",
    }
    workdir = "/opt/bs2/authoring"
    out_cards, report = [], []
    pn, on = vocab.predicate_names(), vocab.operator_names()
    for fam, desc in FAMILIES.items():
        print(f"[authoring] {fam} ...", flush=True)
        cards = author_family(desc, 12, workdir)
        for c in cards:
            if isinstance(c, dict):
                c.setdefault("_family", fam)
                out_cards.append(c)
        print(f"    got {len(cards)} raw cards", flush=True)
    # gate everything
    seen, passed, rejected = {}, [], []
    for c in out_cards:
        r = gate.gate(c, pn, on)
        if r["verdict"] == "PASS":
            k = r["dedup_key"]
            if k in seen:
                continue
            seen[k] = True
            passed.append({"card": c, "gate": r})
        else:
            rejected.append({"card": c, "gate": r})
    import yaml
    yaml.safe_dump([p["card"] for p in passed], open(f"{workdir}/review_queue.yaml", "w"), sort_keys=False)
    json.dump(rejected, open(f"{workdir}/rejected.json", "w"), indent=2)
    print(f"\n=== PILOT RESULT ===")
    print(f"raw authored: {len(out_cards)}   PASS+dedup: {len(passed)}   REJECT: {len(rejected)}")
    print(f"review queue -> {workdir}/review_queue.yaml")
