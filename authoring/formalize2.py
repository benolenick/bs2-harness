#!/usr/bin/env python3
"""Robust re-formalize of the still-prose exploit/privesc/cred cards. Terra, small batches,
KEEPS ORIGINAL on any failure (never drops a card). Overlays onto deck_final.yaml in place."""
import sys, os, json, re, yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0,'/opt/bs2/authoring'); sys.path.insert(0,'/opt/bs2')
import author, vocab, gate
from formalize import RULES, LEGAL_EMITS, dsl_ok, build_prompt   # guarded now; safe import
author.MODEL_ARGS=["-m","gpt-5.6-terra"]
DECK="/opt/bs2/catalog/deck_final.yaml"
def formalize_batch(cards, wd):
    try:
        raw=author.call_codex(build_prompt(cards), wd, timeout=480)
        arr=author._extract_json_array(raw) or []
        byid={c["id"]:c for c in arr if isinstance(c,dict) and "id" in c}
        out=[]
        for orig in cards:
            nc=byid.get(orig["id"])
            if not nc: out.append((orig,"MISS")); continue
            sif=(nc.get("verify") or {}).get("success_if",""); emits=(nc.get("verify") or {}).get("emits",[]) or []
            if not dsl_ok(sif): out.append((orig,"BADDSL")); continue
            if any(e not in LEGAL_EMITS for e in emits): out.append((orig,"BADEMIT")); continue
            if gate.gate(nc, vocab.predicate_names(), vocab.operator_names())["verdict"]=="REJECT": out.append((orig,"REJ")); continue
            out.append((nc,"OK"))
        return out
    except Exception:
        return [(c,"ERR") for c in cards]   # keep originals, never drop
def main():
    missing=set(json.load(open('/tmp/missing_ids.json')))
    deck=yaml.safe_load(open(DECK))
    tgt=[c for c in deck if c['id'] in missing]
    print(f"re-formalizing {len(tgt)} still-prose cards on terra")
    wd="/tmp/claude-1000/-home-om/067fda82-0b60-4e34-84fb-abc54359c68c/scratchpad/formalize2"; os.makedirs(wd,exist_ok=True)
    B=4; batches=[tgt[i:i+B] for i in range(0,len(tgt),B)]
    fixed={}; stats={}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs=[ex.submit(formalize_batch,b,wd) for b in batches]
        for f in as_completed(futs):
            for card,st in f.result():
                stats[st]=stats.get(st,0)+1
                if st=="OK": fixed[card['id']]=card
            print(f"  ...stats {stats}")
    # overlay
    out=[fixed.get(c['id'],c) for c in deck]
    yaml.safe_dump(out, open(DECK,"w"), sort_keys=False)
    formal=sum(1 for c in out if dsl_ok((c.get('verify') or {}).get('success_if','')))
    print(f"\nnewly formalized: {len(fixed)}/{len(tgt)} | stats {stats}")
    print(f"deck_final.yaml now {len(out)} cards, {formal} FORMAL")
if __name__=="__main__":
    main()
