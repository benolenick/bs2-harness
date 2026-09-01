# Ariadne — the attack-path planner behind BS2

Ariadne is the symbolic planner the BS2 manager consults each step. Given the
**confirmed facts** about a target and a **goal**, it returns ranked operator
chains (attack paths) toward that goal — grounded in a curated operator corpus
(web exploitation, Linux privesc via GTFOBins, and full Active Directory + ADCS)
plus an offline Exploit-DB index for exploit-existence lookups.

It is **advisory only**: its output becomes *proposed* graph nodes. It never
authorizes a tool, promotes a fact, or marks work complete — the governed door
and the manager do that.

## How BS2 talks to it

The engine clients (`live/autoturret_planner.py`, `live/ariadne_translate.py`)
speak plain HTTP to `http://127.0.0.1:8112` (override with `GB_ARIADNE` /
`ARIADNE`). Start the server before a run:

```bash
cd ariadne
python3 ariadne/server.py            # serves :8112  (ARIADNE_PORT to change)
```

Routes: `GET /health`, `POST /plan`, `POST /recon`, `POST /extract`,
`GET /exploits`. `/plan` takes `{facts, goal, negatives}` and returns ranked
`paths`. Without the server up, BS2 still runs — it just loses path ranking
(advisory-only by design).

## Requirements

```bash
pip install pyyaml
```

Pure stdlib otherwise (`http.server`). `/extract` optionally calls a local
OpenAI-compatible model at `127.0.0.1:8000` — not needed for `/plan`/`/recon`.

## Corpus provenance

The operator/knowledge corpus (`ariadne/corpus/`) and the Exploit-DB index
(`data/edb_index.jsonl`) are built from public sources — GTFOBins, Exploit-DB,
and PayloadsAllTheThings/HackTricks-style write-ups. Regenerate with the scripts
in `tools/`.

## Tests

```bash
cd ariadne && python3 -m pytest tests/ -q
```
