import yaml, json, sys, re, collections
sys.path.insert(0, '.')
import gate, vocab
passed = yaml.safe_load(open('review_queue.yaml')) or []
rej = [x['card'] for x in json.load(open('rejected.json'))]
raw = passed + rej
pn, on = vocab.predicate_names(), vocab.operator_names()
seen = {}; P = []; R = []
for c in raw:
    r = gate.gate(c, pn, on)
    if r['verdict'] == 'PASS':
        k = r['dedup_key']
        if k in seen: continue
        seen[k] = 1; P.append((c, r))
    else:
        R.append((c, r))
print(f"raw {len(raw)}  ->  PASS+dedup {len(P)}   REJECT {len(R)}")
cc = collections.Counter()
for c, r in R:
    for p in r['problems']:
        cc[re.sub(r"'[^']*'", "'X'", p)] += 1
print("remaining reject reasons:")
for k, v in cc.most_common():
    print(f"  {v:3d}  {k}")
yaml.safe_dump([c for c, _ in P], open('review_queue.yaml', 'w'), sort_keys=False)
