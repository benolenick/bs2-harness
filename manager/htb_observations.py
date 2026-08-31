#!/usr/bin/env python3
"""htb_observations — turn the HTB driver's scrubbed prose facts into the (apps, proven,
extra_facts) triple that ariadne_translate/advise_from_state actually understand.

WHY: run_htb was handing Ariadne freeform strings ("web8080=Apache/2.4.41:Support Center").
translate_state parses only apps{app:ver} + specific proven keys, so EVERY such fact dropped
-> facts_n:0 -> Ariadne planned off generic priors, blind to the box. This bridge folds each
observation into the controlled predicate vocabulary so the possibility-graph actually grounds.

Content-blind: we reason over fact KEYS + product/app names + coarse signal words, never over
raw exploit output. Everything emitted is an OBSERVABLE precondition; speculative chaining stays
Ariadne's job. Anything we can't honestly justify, we don't emit.
"""
from __future__ import annotations
import re

# recognised APPLICATIONS (not bare servers) -> Ariadne app fingerprint. These drive
# vuln_present + live known_exploit arming. Bare apache/nginx are context, emitted as
# endpoint facts only (arming CVEs off "apache" is noise, not signal).
_APP_SIGNS = [
    ("gitlab",     r"gitlab"),
    ("wordpress",  r"wordpress|wp-content|wp-login|wp-json|wp-admin|/wp-"),
    ("drupal",     r"drupal"),
    ("joomla",     r"joomla"),
    ("osticket",   r"osticket|support\s*center|/scp/"),
    ("tomcat",     r"tomcat|coyote|/manager/html"),
    ("jenkins",    r"jenkins|hudson"),
    ("phpmyadmin", r"phpmyadmin"),
    ("jira",       r"atlassian\s*jira|/jira"),
    ("confluence", r"confluence"),
    ("grafana",    r"grafana"),
]
_VER = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

# coarse signal words -> single-arg predicate. Emitted as extra_facts (pre-validated ground
# facts merged straight into the graph). Arg is a stable non-secret handle.
_SIGNAL_PREDS = [
    ("injectable",           r"\bsqli\b|sql\s*inject|injectable|sqlmap.*(?:vulnerable|inject)|union\s+select|' or '1'='1"),
    ("nosql_injectable",     r"nosql|\$ne\b|\$gt\b|mongo.*inject"),
    ("ldap_injectable",      r"ldap\s*inject|ldap_injectable"),
    ("serves_file_by_param", r"\blfi\b|local\s*file\s*includ|\.\./|/etc/passwd|file=|page=|include="),
    ("xxe_vulnerable",       r"\bxxe\b|xml\s*external"),
    ("insecure_deserialization", r"deserializ|unserialize|__wakeup|gadget\s*chain"),
    ("reset_flow",           r"password\s*reset|forgot\s*password|reset\s*token"),
    ("db_backed",            r"login\s*form|mysql|mariadb|postgres|mssql|database|db_engine"),
]
_TEMPLATE_ENGINES = [("jinja2", r"jinja|\{\{.*\}\}|ssti.*python"),
                     ("twig",   r"twig|ssti.*php"),
                     ("freemarker", r"freemarker")]


def _adjacent_ver(text: str, product: str) -> str:
    """Return a version immediately beside product, never one elsewhere on the line."""
    token = rf"(?<![A-Za-z0-9]){re.escape(product)}(?![A-Za-z0-9])"
    separator = r"[\s/:=_-]*"
    version = rf"(?:v(?:ersion)?\s*)?{_VER.pattern}"
    after = re.search(rf"{token}{separator}{version}", text, re.I)
    if after:
        return after.group(1)
    before = re.search(rf"{version}{separator}{token}", text, re.I)
    return before.group(1) if before else ""


def obs_to_graph(facts):
    """facts: list of scrubbed 'key=value' strings (or bare tokens) from the run's map.
    Returns (apps, proven, extra_facts) ready for advise_from_state(proven, apps,
    extra_facts=extra_facts). Pure/offline — no network, safe to unit-test."""
    blob = "\n".join(facts).lower()
    apps, proven, extra = {}, [], []

    # ---- application fingerprints -> apps{app:ver} (drives vuln_present + known_exploit) ----
    for app, pat in _APP_SIGNS:
        m = re.search(pat, blob, re.I)
        if not m:
            continue
        # Detection aliases (for example a characteristic path) can identify an app, but a
        # version binds only when it is directly adjacent to that product's own name token.
        # This prevents a server version elsewhere on the line from bleeding into the app.
        apps[app] = next((version for line in facts
                          if (version := _adjacent_ver(line, app))), "")

    # ---- web endpoints (endpoint/1) from web<port>= facts ----
    for f in facts:
        k = f.split("=", 1)[0].strip().lower()
        mp = re.match(r"web(\d+)", k)
        if mp:
            extra.append(["endpoint", f"http_{mp.group(1)}"])

    # ---- coarse vuln signals -> single-arg predicates (extra_facts) ----
    for pred, pat in _SIGNAL_PREDS:
        if re.search(pat, blob, re.I):
            # bind to the first web endpoint if we have one, else the host-generic handle
            ep = next((x[1] for x in extra if x[0] == "endpoint"), "web")
            extra.append([pred, ep])
    for eng, pat in _TEMPLATE_ENGINES:
        if re.search(pat, blob, re.I):
            ep = next((x[1] for x in extra if x[0] == "endpoint"), "web")
            extra.append(["template_engine", ep, eng])

    # ---- grounded compromise facts -> translate_state's proven vocabulary ----
    for f in facts:
        k, _, v = f.partition("=")
        k = k.strip().lower(); v = v.strip()
        if re.search(r"shell|foothold|rce|www-data|meterpreter", f, re.I) and "denied" not in f.lower():
            u = "www-data"
            mu = re.search(r"as\s+([a-z0-9_\-]+)|shell=([a-z0-9_\-]+)", f, re.I)
            if mu:
                u = mu.group(1) or mu.group(2)
            proven.append(f"shell={u}")
        if k in ("cred", "creds", "credential") and ":" in v:
            proven.append(f"cred={v}")
        if re.search(r"\bhash\b|phpass|\$P\$|bcrypt|\$2[aby]\$|md5|sha1", f, re.I) and k not in ("axfr",):
            mh = re.search(r"(\$[0-9a-zA-Z$./]{6,})", f)
            proven.append(f"hash={mh.group(1) if mh else k+'_hash'}")
        if re.search(r"domain\s*admin|dc_owned|got\s*da\b|ntds", f, re.I):
            proven.append("dc_owned=true")

    # de-dup, preserve order
    def _uniq(seq):
        seen, out = set(), []
        for x in seq:
            key = tuple(x) if isinstance(x, list) else x
            if key not in seen:
                seen.add(key); out.append(x)
        return out

    return apps, _uniq(proven), _uniq(extra)


if __name__ == "__main__":
    demo = ["ports=21,22,25,53,80,110,111,143,993,995,8080",
            "dns_banner=1337_HTB_DNS", "axfr=denied",
            "ftp=anonymous:readable:flag.txt",
            "web80=Apache/2.4.41 (Ubuntu):Inlanefreight",
            "web8080=Apache/2.4.41:Support Center osTicket /scp/login.php",
            "sqli=login.php username injectable (sqlmap confirmed)",
            "lfi=index.php?file=../../etc/passwd works",
            "cred=admin:Welcome1", "hash=$P$Bxxxxx phpass wp_users"]
    a, p, e = obs_to_graph(demo)
    import json
    print("apps   :", json.dumps(a))
    print("proven :", json.dumps(p))
    print("extra  :", json.dumps(e))
