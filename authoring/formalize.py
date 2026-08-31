#!/usr/bin/env python3
"""Formalize exploit/privesc/cred success_if gates into om-b9's engine DSL so they auto-ground.
LEADS (searchsploit/nmap-vuln/nuclei) -> formal match on tool output, emit vuln_present.
LANDINGS (payload exec) -> run `id`, gate uid=, emit rce_as (bridge maps ->shell)."""
import sys, os, json, re, yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0,'/opt/bs2/authoring'); sys.path.insert(0,'/opt/bs2')
import author, vocab, gate
author.MODEL_ARGS = ["-m","gpt-5.6-sol"]   # Ben cleared heavy usage; correctness-critical

DECK="/opt/bs2/catalog/deck_final.yaml"
OUT ="/opt/bs2/catalog/deck_final_v2.yaml"
LEGAL_EMITS={"rce_as","controls_principal","has_hash","vuln_present","known_exploit","pwn_host",
             "session","has_session","reads_file","suid_binary","gtfobin"}

# --- DSL validator: mirror the grammar om-b9's gate.py parses ---
DSL_TOKENS={"exit_code","stdout","stderr","contains","matches","==","!=","&&","||","and","or","(",")"}
def dsl_ok(s):
    if not s: return False
    stripped=re.sub(r"'[^']*'", " STR ", s)          # remove single-quoted literals
    stripped=re.sub(r"\bSTR\b"," ",stripped)
    stripped=re.sub(r"\b\d+\b"," ",stripped)          # numbers (exit codes)
    stripped=stripped.replace("("," ( ").replace(")"," ) ")
    for tok in stripped.split():
        if tok not in DSL_TOKENS: return False
    return ("stdout" in s or "stderr" in s or "exit_code" in s)

RULES=r"""You are formalizing pentest recipe-card SUCCESS GATES so a deterministic engine can auto-verify them.
Rewrite each card's verify.success_if into this EXACT formal DSL (nothing else parses):
  clauses: `exit_code == N` | `exit_code != N` | `stdout contains '<literal>'` | `stderr contains '<literal>'`
           | `stdout matches '<regex>'` | `stderr matches '<regex>'`
  joined by && || and or, optional ( ). Single-quoted literals/regex only. NO prose, NO {{vars}} in the gate.

CLASSIFY each card:
- LANDING (the invocation actually EXECUTES code on the target: metasploit exploit, cmd-injection, deserialization,
  uploaded webshell, SSTI-to-RCE, gitlab/struts/drupal RCE, authenticated code-exec):
    * EDIT the invocation so it PROVES exec by running `id` (append '; id' for shell payloads, set the payload
      command / SET CMD to `id`, or add a webshell fetch of ...=id). Keep it generic/templated ({{host}} etc).
    * success_if = `exit_code == 0 && stdout matches 'uid=\d+\('`
    * for cards that specifically yield ROOT: success_if = `stdout contains 'uid=0(root)'`
    * verify.emits = ["rce_as"]
- LEAD (only LOOKS UP / fingerprints a vuln, no exec: searchsploit, nmap --script *-vuln, nuclei, version->CVE):
    * DO NOT claim rce. success_if = formal match on the tool's positive output, e.g.
      searchsploit -> `exit_code == 0 && stdout contains 'Exploit'`
      nmap vuln    -> `stdout contains 'VULNERABLE'`
      nuclei       -> `exit_code == 0 && stdout matches '\['`
    * verify.emits = ["vuln_present"]
- PRIVESC: gate the concrete proof: root shell `stdout contains 'uid=0(root)'`; readable shadow
    `stdout matches 'root:[^:]*:\d'`; SUID hit `stdout matches 'rws'`. emits ["rce_as"] if it yields a root shell,
    else ["vuln_present"].
- CRED/hash: gate the literal secret in stdout: hash `stdout matches '\$[0-9a-zA-Z]{1,3}\$'`;
    NTLM `stdout matches ':[0-9a-f]{32}'`; found-cred lines from the tool. emits ["has_hash"] for hashes,
    ["controls_principal"] for usable creds.

HARD: emits MUST be from this set ONLY: rce_as, controls_principal, has_hash, vuln_present, known_exploit, pwn_host.
Keep id, name, phase, tier, autonomy, when, tool, parallel_safe, blast_radius, operator, confirms, cost_hint, notes.
Return ONLY a JSON array of the SAME cards (same ids, same count) with edited invocation/success_if/emits."""

def build_prompt(cards):
    return (RULES+"\n\nCARDS (JSON):\n"+json.dumps(cards,indent=0)+
            f"\n\nReturn a JSON array of exactly {len(cards)} cards. No prose, no fences.")

def formalize_batch(cards, wd, i):
    try:
        raw=author.call_codex(build_prompt(cards), wd, timeout=600)
        arr=author._extract_json_array(raw)
        if not arr: return None
        byid={c["id"]:c for c in arr if isinstance(c,dict) and "id" in c}
        out=[]
        for orig in cards:
            nc=byid.get(orig["id"])
            if not nc: out.append((orig,"MISSING")); continue
            sif=(nc.get("verify") or {}).get("success_if","")
            emits=(nc.get("verify") or {}).get("emits",[]) or []
            if not dsl_ok(sif): out.append((orig,"BAD-DSL")); continue
            if any(e not in LEGAL_EMITS for e in emits): out.append((orig,"BAD-EMIT")); continue
            g=gate.gate(nc, vocab.predicate_names(), vocab.operator_names())
            if g["verdict"]=="REJECT": out.append((orig,"GATE-REJECT")); continue
            out.append((nc,"OK"))
        return out
    except Exception as e:
        return [(c,f"ERR:{e}") for c in cards]

def main():
    deck=yaml.safe_load(open(DECK)) or []
    targets=[c for c in deck if c.get("phase") in ("exploit","privesc","cred")]
    passthrough=[c for c in deck if c.get("phase") not in ("exploit","privesc","cred")]
    print(f"deck {len(deck)} | to-formalize {len(targets)} (exploit/privesc/cred) | passthrough {len(passthrough)}")
    B=8; batches=[targets[i:i+B] for i in range(0,len(targets),B)]
    wd="/tmp/claude-1000/-home-om/067fda82-0b60-4e34-84fb-abc54359c68c/scratchpad/formalize"
    os.makedirs(wd,exist_ok=True)
    results=[]; stats={}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs={ex.submit(formalize_batch,b,wd,i):i for i,b in enumerate(batches)}
        for f in as_completed(futs):
            r=f.result() or []
            for card,status in r:
                stats[status]=stats.get(status,0)+1
                results.append(card)  # OK->formalized card; else original (never lose a card)
            done=sum(1 for x in stats); print(f"  batch {futs[f]} done | running stats {stats}")
    final=passthrough+results
    yaml.safe_dump(final, open(OUT,"w"), sort_keys=False)
    print(f"\nSTATS: {stats}")
    formal=sum(1 for c in results if dsl_ok((c.get('verify') or {}).get('success_if','')))
    print(f"formalized (parseable DSL) among targets: {formal}/{len(targets)}")
    print(f"wrote {len(final)} cards -> {OUT}")
if __name__=="__main__":
    main()
