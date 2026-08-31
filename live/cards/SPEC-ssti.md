# CARD: ssti  (server-side template injection -> RCE)
Read CONTRACT.md first. Write the card to /opt/bs2/live/cards/ssti.py exposing fire(rx, lane).

Detect: pick reflected inputs — GET query params on the app's pages and visible <form> fields
(crawl a page or two from rx.bind http, honoring rx._hh() for the app vhost). Inject a polyglot
that is safe and unambiguous, e.g. `${{7*7}}` variants and `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`,
`#{7*7}`. Confirm the engine by finding the evaluated result `49` reflected back (and NOT the
literal `7*7`).
Exploit: once an engine is identified (Jinja2/Twig/Freemarker/Velocity/ERB/Smarty), send that
engine's command-exec payload to run `id` and read output in the same response.
Verify: success only if you see `uid=` in the response. Emit facts: `finding=ssti@<param-or-form>`,
`rce_as=<user>`, and `shell=<user>` if code exec is confirmed; grab any HTB{...} the RCE prints.
Fail safe: no `49` reflection anywhere -> return None.
NO target-specific literals. Derive URLs/params/vhosts from rx.* and your crawl only.
