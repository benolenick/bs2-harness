# TASK: author a web-app attack card deck for the AUTOTURRET catalog

You are extending an autonomous pentest engine's card catalog. The engine has 591 cards but
only 9 touch web apps — it goes DRY against web targets like OWASP Juice Shop. Author a
comprehensive web-app card set, and VALIDATE each card live so only cards that actually work ship.

AUTHORIZED TARGET (local, deliberately-vulnerable, non-destructive only):
  http://127.0.0.1:3060   (OWASP Juice Shop, running now)
Hit ONLY that target. Read-only/non-destructive requests only (probing/injection that reads data
is fine; do NOT delete, mass-mutate, or DoS). Ground truth board: curl -s http://127.0.0.1:3060/api/Challenges/

## WHERE TO WRITE
- Write cards to a NEW self-contained file: /opt/bs2/catalog/web_cards.yaml
  (a YAML LIST of card dicts — same shape as deck_final.yaml items). Do NOT edit deck_final.yaml.
- Also write /opt/bs2/catalog/web_cards.report.md: one line per card —
  `id  PHASE  VERDICT(hit|miss|staged)  fclass  <one-line non-secret note>`.
  Keep it NON-SECRET: never paste tokens, passwords, hashes, or response bodies. Technique names
  and endpoint paths only.

## EXACT CARD SCHEMA (copy these field names precisely)
```yaml
- id: web-sqli-login-auth-bypass         # unique kebab-case
  name: Login SQLi auth bypass            # human label (non-secret)
  phase: exploit                          # recon|enum|loot|cred|lateral|exploit|privesc
  tier: standard
  autonomy: full                          # full = AUTOFIRES unattended; semi/manual = staged for approval
  when:                                   # preconditions; matched against grounded facts
  - service: http                         # <-- PRIMARY key: juice grounds service=http, so this fires
  tool: curl
  invocation: >-                          # shell command; {{vars}} filled by the engine
    curl -ksS -X POST {{target}}/rest/user/login -H 'Content-Type: application/json'
    --data '{"email":"admin@juice-sh.op'"'"' OR 1=1--","password":"x"}'
  parallel_safe: true
  blast_radius: low                       # none|low|medium|high
  operator: ''
  confirms:
  - session
  verify:
    success_if: exit_code == 0 && stdout contains 'authentication'
    emits:
    - admin_jwt
  cost_hint: cheap
  notes: Non-destructive read; names the /rest/user/login endpoint.
```

## HARD RULES that make a card actually FIRE and HIT

1. **{{target}} is the full base URL** (for this run, `http://127.0.0.1:3060`). Build every URL as
   `{{target}}/path`. Do NOT use `{{host}}:{{port}}` for these web cards (port defaults to 80 and
   breaks a :3060 target). {{target}} works.

2. **tool**: prefer `curl` and `python3` (always installed). You MAY author cards using `sqlmap`,
   `jwt_tool`, `ffuf` etc., but mark those `autonomy: semi` (they stage rather than autofire, so a
   missing binary never breaks the sweep). Cards you want to AUTOFIRE and prove-hit must use
   curl/python3 so they run everywhere.

3. **success_if grammar is a STRICT deterministic mini-language — stay inside it or the engine
   falls back to an LLM judge.** Allowed:
   - atoms: `exit_code == 0` , `exit_code != 0` , `stdout contains 'STR'` , `stdout matches 'REGEX'`
     (idents usable: exit_code, stdout, stderr; response/output/report alias stdout)
   - logic: `&&` `||` (or `and`/`or`), with parentheses
   - Example: `exit_code == 0 && (stdout contains 'token' || stdout matches 'eyJ[A-Za-z0-9_-]+')`
   Design each success_if to match a UNIQUE, RELIABLE marker of success (a challenge-solved JSON
   key, a leaked field name, an error string that proves injection, a base64 JWT prefix `eyJ`),
   NOT something a normal 200 also contains.

4. **emits** = fact keys grounded on a hit; they unlock downstream cards. Use DESCRIPTIVE web keys:
   `sqli, auth_bypass, admin_jwt, idor, bac, nosqli, xss, path_traversal, ssti, ssrf, xxe,
   cmd_injection, sensitive_exposure, endpoint, session`. **Never emit `shell`, `cred`, `hash`,
   or `flag` UNLESS the raw output literally proves it** (uid= for shell; the secret present for
   cred/hash) — the engine's phantom-foothold guard will reject an unproven compromise emit and
   flag the card for review. Descriptive keys above are always safe to emit on a gate-true.

5. **autonomy**: `full` only for safe, non-destructive, self-contained probes/injections (GET or a
   read-only POST that doesn't change server state). Anything that writes/mutates → `semi`.

6. Fill every field: tier(standard), operator(''), parallel_safe(true for independent probes),
   blast_radius, confirms, cost_hint(cheap|moderate). `when: [{service: http}]` on ALL of them so
   they're eligible on any http target; you MAY add a second guarded variant with
   `when: [{service: http}, {product: juice-shop}]` for juice-specific payloads.

## COVERAGE TARGET (author multiple cards per class; aim ~35-50 total)
- **SQLi**: login auth-bypass (admin + first-user `'--`), UNION product search
  (`/rest/products/search?q=`), order-by/error-based enumeration.
- **Broken auth / JWT**: forge `alg:none` token, `Authorization: Bearer` acceptance probe,
  password-reset/security-question flows, oauth/`/rest/user/whoami` leak.
- **Broken access control / IDOR**: basket walk (`/rest/basket/{id}`), other users' feedback,
  admin-only endpoints reachable (`/api/Users`, `/rest/admin/*`), review author spoof.
- **NoSQLi**: `$ne`/`$gt`/`$regex` operator injection where juice uses Mongo-style query params.
- **XSS**: reflected (search `<iframe src=javascript:...>`), DOM, stored (feedback/product review
  sinks) — success_if on the payload being reflected unescaped.
- **Path traversal / file access**: `/ftp` directory listing, `%2e%2e%2f` static escape, poison-null
  `%00.md` bypass, backup files (`/ftp/legal.md`, `.bak`, `package.json.bak`).
- **Sensitive-data exposure**: `/.git/HEAD`, exposed metrics/`/metrics`, `/rest/admin/application-configuration`,
  error-stack leakage, `/redirect?to=` open-redirect/SSRF.
- **SSTI / SSRF / XXE / command-injection**: where an input is templated, fetched, XML-parsed, or
  shelled — one card each even if it stages.

## VALIDATION (this is the point — ship only cards that work)
For EACH card you author: run its invocation against http://127.0.0.1:3060 yourself (substitute
{{target}} manually), observe the output, and confirm your success_if would evaluate TRUE on a real
hit and FALSE on a clean 200/404. Only keep cards whose success_if reliably discriminates. Record
the live verdict in web_cards.report.md. If a technique doesn't work on this juice-shop build, keep
the card but mark it `staged` in the report and set its autonomy to `semi` (don't ship a false hit).

When done, print: total cards, count validated-HIT, count staged, and the two file paths.
