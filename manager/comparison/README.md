# BS2 ⇄ MIT comparison kit

Put both harnesses on the same target, same schema, same scorer.

- **`MIT_HARNESS_RUNBOOK.md`** — hand this to the MIT-harness owner. How to run, what to fill.
- **`score_run.py`** — the shared scorer. Full schema in its top docstring. Symmetric: any
  reweighting hits both harnesses.
- **`BS2_vs_MIT_COMPARISON.md`** — the head-to-head write-up (BS2 filled, MIT pending).
- **`runs/`** — one JSON per run:
  - `bs2_crapi_sonnet.json` — BS2 on crAPI (4/4 verified) → **93.7**
  - `bs2_enterprise163.json` — BS2 on HTB multi-hop AD
  - `bs2_crapi_deepseek.json` — BS2 machinery, DeepSeek hands (model-agnostic demo)
  - `mit_STUB_fill_me.json` — copy to `mit_crapi.json`, fill, score

## One-liners
```bash
python3 score_run.py runs/bs2_crapi_sonnet.json                    # one run
python3 score_run.py runs/bs2_crapi_sonnet.json runs/mit_crapi.json  # side-by-side + delta
```
