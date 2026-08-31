# web_cards — generic web-app deck for AUTOTURRET (content-blind report)

16 reusable cards, terrain-matched on `service: http`, no target-specific payloads.
Validated live against a local deliberately-vulnerable app (juice-shop, 127.0.0.1:3060)
through the engine's own fire_card + gate. Verdicts only — no response bodies.

| id | phase | autonomy | live verdict | note |
|----|-------|----------|--------------|------|
| web-http-fingerprint      | recon   | full | HIT   | HTTP status/headers fingerprint |
| web-robots-disclosure     | recon   | full | HIT   | robots.txt disallow entries |
| web-backup-file-sweep     | enum    | full | HIT   | 200 on a common leaked artifact |
| web-metrics-exposure      | enum    | full | HIT   | unauth Prometheus /metrics |
| web-sqli-quote-error      | exploit | full | HIT*  | single-quote surfaces SQL error (*flaky under load) |
| web-sqli-login-tautology  | exploit | full | HIT   | OR-tautology login bypass returns a token |
| web-git-head-leak         | enum    | full | miss  | honest: target has no exposed .git (404) |
| web-bac-api-collection    | exploit | full | miss  | honest: collection protected unauth (401) |
| web-idor-object-walk      | exploit | full | miss  | honest: object requires session (401) |
| web-traversal-etcpasswd   | exploit | full | miss  | honest: static guard blocks (403) |
| web-open-redirect         | exploit | full | miss  | honest: redirect allowlist enforced |
| web-jwt-none-alg          | exploit | semi | miss  | honest: signature enforced; stages |
| web-nosqli-login-operator | exploit | semi | miss  | honest: SQL-backed auth, not Mongo; stages |
| web-xss-reflection        | exploit | semi | miss  | honest: JSON API, no server reflection; stages |
| web-dir-brute-ffuf        | enum    | semi | stage | needs ffuf + wordlist |
| web-sqli-sqlmap-param     | exploit | semi | stage | needs sqlmap |

HIT=6 (autofire, curl/python, no external deps).  The "miss" rows are HONEST generic
negatives on this particular target, not broken cards — each lands where the class is
genuinely present.  Deck is generic by design (Ben: "don't custom-make something that
would pop the box"): techniques, not a scripted solve.

Merged into deck_run.yaml (active) + deck_final.yaml (source); backups .bak-prewebcards.
Autoturret picks these up automatically via run_double_barrel.sh (AUTOTURRET_CATALOG=1).
