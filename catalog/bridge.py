"""
bridge.py — fire terrain-matched catalog cards through the trooper, verify by the gate.

This is the loader -> engine join (task A). It is CONTENT-BLIND end to end:
  - selects cards whose `when` preconditions hold against the engine's grounded facts
  - fills {{placeholders}} from discovered terrain + config defaults
  - executes the DETERMINISTIC card invocation via trooper.run_cmd (governed_exec, scope-guarded)
  - captures the real exit code (run_cmd hides it) via an appended __GBRC marker
  - verdicts each fire with gate.evaluate: True -> ground verify.emits ; False -> miss ;
    None (prose/unparseable gate) -> INDETERMINATE, flagged for human / smarter-AI review

The manager never sees an invocation or its output — only labels + fact KEYS (the scrub contract).
"""
import os, re, sys, json, urllib.request
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import loader, gate

# ---- phantom-foothold guard: mirror the engine's grounded() proof for compromise emits ----
# An LLM judge (below) can say "hit" on a prose gate, but a COMPROMISE emit (shell/cred/hash/flag)
# still may not ground unless the raw output actually PROVES it. Same discipline the engine uses
# in apply(), applied here so the catalog path can't ground a phantom foothold either.
COMPROMISE = {"shell", "cred", "dc_cred", "hash", "flag", "dc_owned"}
# card emits use Ariadne predicates; the engine grounds engine fact-keys. Map the compromise-grade
# ones so an `rce_as` emit is grounded as a uid=-proven `shell`, not a free-pass fact.
# Only Ariadne-legal predicates (om-e3 confirmed): rce_as/controls_principal/has_hash.
EMIT_ALIAS = {"rce_as": "shell", "controls_principal": "cred", "has_hash": "hash"}
def proves_compromise(emit_key, stdout):
    ev = stdout or ""
    if emit_key in ("shell", "dc_owned"): return bool(re.search(r"uid=\d+\(", ev))
    if emit_key in ("cred", "dc_cred", "hash"): return bool(ev.strip())  # secret must be present-ish
    if emit_key == "flag": return bool(re.search(r"[A-Za-z0-9]{16,}|HTB\{", ev))
    return True

# ---- prose-gate verifier tier: a cheap LLM judges the (rc, stdout) against the NL criterion ----
# Runs on the trooper/judge tier (deepseek-flash by default) — which already sees raw output — so
# the MANAGER stays content-blind (it only ever receives the verdict, never this text).
JUDGE_BASE  = os.environ.get("GB_JUDGE_BASE",  "https://api.deepseek.com")
JUDGE_MODEL = os.environ.get("GB_JUDGE_MODEL", "deepseek-chat")  # api.deepseek.com direct model id
JUDGE_KEYF  = os.environ.get("GB_JUDGE_KEY_FILE", os.path.join(os.path.dirname(_HERE), ".ds_key"))
JUDGE_ON    = os.environ.get("GB_JUDGE", "1") not in ("0", "false", "no", "")

def _judge_key():
    k = os.environ.get("GB_JUDGE_KEY", "").strip()
    if k: return k
    try:
        with open(JUDGE_KEYF) as f: return f.read().strip()
    except Exception: return ""

def llm_judge(success_if, rc, stdout):
    """Return True(hit) / False(miss) / None(unclear or unavailable). Never raises."""
    if not JUDGE_ON: return None
    key = _judge_key()
    if not key and "127.0.0.1" not in JUDGE_BASE and "localhost" not in JUDGE_BASE:
        return None
    sys_p = ("You verify penetration-test command results. Given a success CRITERION in natural "
             "language, the exit code, and the command OUTPUT, decide if the criterion is met. "
             "Be strict: if the output does not clearly satisfy it, answer miss or unclear. "
             'Reply ONLY compact JSON: {"verdict":"hit"} or {"verdict":"miss"} or {"verdict":"unclear"}.')
    usr = f"CRITERION: {success_if}\nEXIT_CODE: {rc}\nOUTPUT (truncated):\n{(stdout or '')[:2500]}"
    body = json.dumps({"model": JUDGE_MODEL, "temperature": 0, "max_tokens": 40, "stream": False,
                       "messages": [{"role": "system", "content": sys_p},
                                    {"role": "user", "content": usr}]}).encode()
    hdr = {"Content-Type": "application/json"}
    if key: hdr["Authorization"] = "Bearer " + key
    try:
        req = urllib.request.Request(JUDGE_BASE.rstrip("/") + "/chat/completions", body, hdr)
        with urllib.request.urlopen(req, timeout=30) as r:
            txt = json.load(r)["choices"][0]["message"]["content"]
        m = re.search(r'"verdict"\s*:\s*"(hit|miss|unclear)"', txt)
        if not m: return None
        return {"hit": True, "miss": False, "unclear": None}[m.group(1)]
    except Exception:
        return None

# Config-y placeholders that are operator defaults, not discovered terrain.
DEFAULTS = {
    "wordlist":   "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "userlist":   "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "passlist":   "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "resolver_list": "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
    "resolvers":  "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
    "candidate_list": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "namelist":   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "threads":    "20", "timeout": "30", "rate": "1000", "depth": "2",
    "aggression": "2", "scheme": "http",
    "status_codes":   "200,204,301,302,307,401,403",
    "filtered_codes": "404",
}
# terrain placeholders we can derive; anything still unfilled after this + DEFAULTS -> card skipped
_OUTISH = ("output", "output_dir", "results_file", "out_file", "report", "target_file",
           "credential_file", "password_file", "local_file", "export", "folder")

def build_ctx(recon):
    """engine recon dict (or lanes/recon.json) -> loader match-context."""
    ctx = loader._blank_ctx()
    # A URL target IS an http(s) service even before any fingerprint grounds an app. Derive the
    # service+port straight from the scheme so web cards (when: service:http) are eligible on any
    # URL engagement — general, not target-specific. Host/IP targets carry no scheme -> unaffected.
    _tgt = str(recon.get("target", "") or "")
    _mu = re.match(r"(https?)://([^/:]+)(?::(\d+))?", _tgt)
    if _mu:
        _scheme = _mu.group(1)
        ctx["services"].add("http")                       # cards gate on the generic 'http' service
        if _scheme == "https":
            ctx["services"].add("https")
        ctx["ports"].add(int(_mu.group(3)) if _mu.group(3) else (443 if _scheme == "https" else 80))
    apps = recon.get("apps", {}) or {}
    facts = recon.get("unlocked_keys", []) or recon.get("facts", []) or []
    proven = [p.get("fact","") if isinstance(p,dict) else str(p) for p in (recon.get("proven_facts") or recon.get("proven") or [])]
    # Web apps imply an HTTP(S) service+port even when the engine only recorded the app name.
    WEB = {"gitlab","wordpress","drupal","joomla","phpmyadmin","apache","nginx","tomcat","apache struts"}
    def note(tok):
        tok = tok.lower(); ctx["products"].add(tok); ctx["services"].add(loader.alias(tok))
        if tok in WEB or tok == "http":
            ctx["services"].add("http"); ctx["ports"].add(80); ctx["ports"].add(443)
    # services the engine bound directly (self.bind = {service: ip}) — live wiring passes this
    PORTS = {"http":80,"https":443,"ftp":21,"ssh":22,"smtp":25,"dns":53,"smb":445,
             "imap":143,"pop3":110,"nfs":2049,"rpcbind":111}
    for svc in list(recon.get("bind", {}) or {}) + list(recon.get("services", []) or []):
        note(svc)
        if svc in PORTS: ctx["ports"].add(PORTS[svc])
    # products/services from fingerprinted apps
    for app in apps: note(app)
    # services/ports parsed out of grounded fact strings (app=/svc=/port=/ftp=/vhost=/dns…)
    for f in proven:
        m = re.match(r"(app|service|svc)=([a-zA-Z0-9_ -]+)", f)
        if m: note(m.group(2).strip())
        m = re.search(r"port=(\d+)", f)
        if m: ctx["ports"].add(int(m.group(1)))
        k = f.split("=",1)[0].strip().lower()
        if k == "ftp":   ctx["services"].add("ftp"); ctx["ports"].add(21)
        if k == "vhost": ctx["services"].add("dns"); ctx["ports"].add(53)
        if k in ("smb","share"): ctx["services"].add("smb"); ctx["ports"].add(445)
        # version-guard: derive drupalgeddon2 applicability from a grounded drupal_version so the
        # CVE-2018-7600 card fires ONLY on an in-range version (<7.58, or 8.x<8.5.1) and stays
        # silent on Drupal 9 / patched (no more blind no-session spam). Card gates on
        # have: drupalgeddon2-applicable. No version grounded -> not applicable -> card holds.
        if k == "drupal_version":
            mv = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", f.split("=",1)[1])
            if mv:
                maj = int(mv.group(1)); mnr = int(mv.group(2) or 0); pat = int(mv.group(3) or 0)
                vulnerable = (maj == 7 and (mnr, pat) < (58, 0)) or (maj == 8 and (mnr, pat) < (5, 1))
                if vulnerable: ctx["have"].add("drupalgeddon2-applicable")
    # ports the engine bound directly (live wiring passes recon['ports'])
    for p in (recon.get("ports") or []):
        try: ctx["ports"].add(int(p))
        except Exception: pass
    # 'have' capabilities from unlocked keys
    keymap = {"cred":"passlist", "creds":"passlist", "hash":"hashes", "hashes":"hashes",
              "user":"userlist", "shell":"foothold", "session":"session",  # session unlocks post-auth cards
              "admin_access":"admin_access"}      # vertical-priv unlock: admin_access -> admin-only cards
    for k in facts:
        if k in keymap: ctx["have"].add(keymap[k])
    ctx["services"] = {loader.alias(x) for x in ctx["services"]}
    return ctx

def resolve_vars(card, target, recon, extra=None):
    """Build the {{placeholder}} -> value map for this card. Missing terrain vars are simply
    absent -> gate.fill returns None -> the card is 'not yet fireable' (correct unlock behavior)."""
    apps = recon.get("apps", {}) or {}
    v = dict(DEFAULTS)
    v["host"] = target; v["target"] = target; v["target_host"] = target
    v["rhost"] = target; v["ip"] = target; v["probe_ip"] = target
    # vhost/domain: prefer an app-bound vhost, else any discovered vhost
    vhosts = [p.get("fact","").split("=",1)[1] for p in (recon.get("proven_facts") or [])
              if isinstance(p,dict) and p.get("fact","").startswith("vhost=")]
    app_vhost = next((h for a,h in apps.items() if isinstance(h,str) and "." in h), "")
    if app_vhost: v["domain"] = app_vhost; v["probe_host"] = app_vhost
    elif vhosts:  v["domain"] = vhosts[0]; v["probe_host"] = vhosts[0]
    # per-card vhost: bind {{vhost}} from THIS card's own product/service so name-based
    # vhosts don't collide (drupal->blog.*, gitlab->gitlab.*, wordpress->careers.*). Overrides
    # the arbitrary global app_vhost pick above for any card whose target app is a named vhost.
    _when = card.get("when", []) or []
    _prod = next((w["product"] for w in _when if isinstance(w,dict) and "product" in w), None) \
            or next((w["service"] for w in _when if isinstance(w,dict) and w.get("service") in apps), None)
    if _prod and isinstance(apps.get(_prod), str) and "." in apps[_prod]:
        v["vhost"] = apps[_prod]; v["domain"] = apps[_prod]; v["probe_host"] = apps[_prod]
    # port hints per common service
    portmap = {"http":80,"https":443,"ftp":21,"ssh":22,"smtp":25,"dns":53,"smb":445}
    for w in card.get("when", []):
        if "port" in w: v.setdefault("port", w["port"])
        if "service" in w and w["service"] in portmap: v.setdefault("port", portmap[w["service"]])
    v.setdefault("port", 80)
    # url from scheme+domain/host+port
    hostpart = v.get("domain") or v["host"]
    v.setdefault("url", f"{v['scheme']}://{hostpart}:{v['port']}/")
    # safe config defaults derivable now (terrain vars like user/module/bin stay unfilled -> stage)
    if v.get("domain"): v.setdefault("zone", v["domain"])
    v.setdefault("lport", "4444")
    v.setdefault("lhost", os.environ.get("GB_LHOST", "").strip())
    # {{vhost}} always fills: named vhost if bound above, else domain, else bare IP (== no Host
    # override). Guarantees a card carrying `set VHOST {{vhost}}` never stages for lack of a vhost.
    v.setdefault("vhost", v.get("domain") or v["host"])
    # {{vhosts}} = space-separated unique grounded vhost names, for recon cards that must sweep
    # every name-based vhost with its own Host header (one card, all vhosts). Absent -> unfilled
    # so a vhost-sweep card stages until at least one vhost grounds.
    _dom = v.get("domain")
    _allv = sorted(set(vhosts) | ({_dom} if _dom and re.search(r"[A-Za-z]", str(_dom)) else set()))
    if _allv: v["vhosts"] = " ".join(_allv)
    # {{git_leak_vhost}} = the exact vhost the .git sweep proved exposed (git_leak_vhost=<host>),
    # so the git-dumper follow-up dumps that one repo with the right Host header. Absent -> unfilled
    # so the git-dumper card STAGES until the sweep grounds a real leak (no phantom dumps).
    for p in (recon.get("proven_facts") or []):
        fact = p.get("fact","") if isinstance(p,dict) else str(p)
        m = re.match(r"git_leak_vhost=(\S+)", fact.strip())
        if m: v.setdefault("git_leak_vhost", m.group(1)); break
    # credentials: fill {{user}}/{{pass}} (+ service-specific {{wp_user}}/{{gitlab_user}}/... and
    # {{username}}/{{password}} aliases) from grounded cred facts. Absent creds stay unfilled ->
    # any auth-gated foothold card stages until the cred lane (phpass crack, brute) grounds a login.
    # Tolerant to shapes:  cred=user:pass | <svc>_cred=user:pass | login=user:pass  (: or / sep).
    for p in (recon.get("proven_facts") or []):
        fact = p.get("fact","") if isinstance(p,dict) else str(p)
        m = re.match(r"(?:(\w+)_)?(?:cred|creds|login)=([^:/\s]+)[:/](.+)$", fact.strip())
        if not m: continue
        svc, usr, pw = m.group(1), m.group(2), m.group(3).strip()
        v.setdefault("user", usr); v.setdefault("pass", pw)
        v.setdefault("username", usr); v.setdefault("password", pw)
        if svc:
            svc = svc.lower()
            alias = {"wordpress":"wp","gitlab":"gitlab","drupal":"drupal","wp":"wp"}.get(svc, svc)
            v.setdefault(f"{alias}_user", usr); v.setdefault(f"{alias}_pass", pw)
    # per-card unique output paths
    cid = card.get("id","card")
    for k in _OUTISH: v.setdefault(k, f"/tmp/gb-{cid}.out")
    v["output_dir"] = f"/tmp/gb-{cid}.d"
    # private secret channel (session tokens / api keys captured by an earlier card) — fills
    # {{token}}/{{session}}/... for post-auth cards WITHOUT the value ever entering facts/telemetry.
    # Absent -> the var stays unfilled -> the post-auth card STAGES until a prior card grounds the
    # session (the correct unlock order; no phantom authenticated requests).
    for _sk, _sv in (recon.get("_secrets") or {}).items():
        if _sv: v.setdefault(_sk, _sv)
    if extra: v.update(extra)
    return v

_RC = re.compile(r"__GBRC=(-?\d+)__")

def _fclass(stdout, rc=None):
    """Content-tier failure categoriser for a card miss. Returns ONLY a safe category label
    (never raw output) so the manager feed can carry WHY a card missed — the signal that tells
    the manager which lever to pull. Most-specific first."""
    t = (stdout or "").lower()
    if not t.strip():                                    return "no-output"
    if "connection refused" in t or "econnrefused" in t: return "conn-refused"
    if "timed out" in t or "timeout" in t:               return "timeout"
    if "could not resolve" in t or "name or service not known" in t or "no such host" in t: return "dns-fail"
    if "no route to host" in t or "network is unreachable" in t: return "net-unreachable"
    if "401" in t or "unauthorized" in t or "authentication required" in t or "login required" in t: return "auth-required"
    if "403" in t or "forbidden" in t:                   return "http-403"
    if "404" in t or "not found" in t:                   return "http-404"
    if "appears to be safe" in t or "not vulnerable" in t or "target is not exploitable" in t or "not exploitable" in t: return "check-not-vulnerable"
    if "exploit completed, but no session" in t or ("no session" in t) or "not created" in t: return "no-session(bind?egress?)"
    if "handler failed to bind" in t or "refused to connect" in t: return "bind-failed"
    if re.search(r"\b5\d\d\b", t) and "http" in t:       return "http-5xx"
    if "200" in t:                                        return "http-200-no-proof"
    if "error" in t or "traceback" in t or "exception" in t: return "tool-error"
    return "no-proof"

def fire_card(card, target, vars, run_cmd):
    """Fill -> exec (deterministic, scope-guarded) -> capture rc -> gate verdict."""
    inv = gate.fill(card["invocation"], vars)
    if inv is None:
        return {"status": "staged", "reason": "missing " + ",".join(gate.missing_vars(card["invocation"], vars))}
    wrapped = inv + ' ; printf "\\n__GBRC=%s__\\n" "$?"'
    raw = run_cmd(wrapped, target)
    if isinstance(raw, str) and raw.startswith("[trooper scope-guard BLOCKED"):
        return {"status": "blocked", "reason": raw}
    m = _RC.search(raw or "")
    rc = int(m.group(1)) if m else None
    stdout = _RC.sub("", raw or "").strip()
    sif = (card.get("verify") or {}).get("success_if", "")
    emits = (card.get("verify") or {}).get("emits", []) or []
    verdict = gate.evaluate(sif, rc, stdout)          # deterministic first (free)
    src = "gate"
    if verdict is None:                                # prose/unparseable -> cheap LLM judge tier
        verdict = llm_judge(sif, rc, stdout)
        src = "judge"
    if verdict is False:
        return {"status": "miss", "rc": rc, "src": src, "fclass": _fclass(stdout, rc)}
    if verdict is None:
        return {"status": "indeterminate", "rc": rc, "gate": sif[:60]}  # human/smarter-AI review
    # verdict True: split emits into PROVEN vs CLAIMED-BUT-UNPROVEN (phantom-foothold guard).
    proven, unproven = [], []
    for e in emits:
        key = EMIT_ALIAS.get(e, e)
        if key in COMPROMISE and not proves_compromise(key, stdout):
            unproven.append(e)
        else:
            proven.append(key)
    # value-capture: a card may declare verify.capture {emit_key: regex-with-group} to surface the
    # PARSED VALUE (e.g. drupal_version=7.57) as a valued fact. ONLY for non-compromise signal keys
    # (version/app/vhost) — compromise values (shell/cred/hash/flag) stay scrubbed to keys. Absent
    # capture or no regex match -> the bare key, unchanged (backward compatible).
    capture = (card.get("verify") or {}).get("capture", {}) or {}
    if capture:
        valued = []
        for key in proven:
            cre = capture.get(key)
            if cre and key not in COMPROMISE:
                try:
                    mm = re.search(cre, stdout)
                    if mm:
                        valued.append(f"{key}={mm.group(1) if mm.groups() else mm.group(0)}"); continue
                except re.error:
                    pass
            valued.append(key)
        proven = valued
    # secret_capture: pull a SENSITIVE value (session token / api key) into a PRIVATE channel that
    # fills downstream {{vars}} but NEVER enters emits/facts/telemetry (content-blind chaining). The
    # bare unlock KEY (e.g. 'session') still rides emits so post-auth cards gate on `have: session`;
    # only the VALUE travels here, out of band, and the caller keeps it off disk and off the panel.
    secrets = {}
    for _vn, _cre in ((card.get("verify") or {}).get("secret_capture", {}) or {}).items():
        try:
            _mm = re.search(_cre, stdout)
            if _mm:
                secrets[_vn] = _mm.group(1) if _mm.groups() else _mm.group(0)
        except re.error:
            pass
    r = {"status": "hit", "rc": rc, "src": src, "emits": proven}
    if secrets:
        r["secrets"] = secrets
    if unproven:                                       # gate/judge said hit, but no hard proof
        r["unproven"] = unproven
    if "shell" in proven and re.search(r"uid=0\(root\)", stdout):
        r["root"] = True                               # content-blind OWNED signal (bool, no output)
    return r

def sweep(recon, target, run_cmd, *, dial="full", phases=None, autofire_only=True, dry=False,
          max_workers=8):
    """Select terrain-matched cards and fire the autofire ones. Returns a per-card result list.
    Fires CONCURRENTLY (each card exec + judge is independent I/O); state-mutation stays with the
    caller. dry=True: select + fill only, never execute (for validating the wire)."""
    import concurrent.futures as _cf
    ctx = build_ctx(recon)
    cat = loader.load_catalog()
    sel = loader.select(ctx, dial=dial, catalog=cat)
    if phases: sel = [r for r in sel if r.get("phase") in phases]
    results = []
    to_fire = []
    for card in sel:
        if autofire_only and not card["_disposition"]["would_autofire"]:
            results.append({"id": card["id"], "phase": card["phase"], "status": "needs-gate"}); continue
        vars = resolve_vars(card, target, recon)
        if dry:
            inv = gate.fill(card["invocation"], vars)
            results.append({"id": card["id"], "phase": card["phase"],
                            "status": "would-fire" if inv else "staged",
                            "cmd": (inv[:90] if inv else None),
                            "reason": None if inv else "missing " + ",".join(gate.missing_vars(card["invocation"], vars))})
            continue
        to_fire.append((card, vars))

    def _one(card, vars):
        r = fire_card(card, target, vars, run_cmd)
        r["id"] = card["id"]; r["phase"] = card["phase"]
        return r
    if to_fire:
        with _cf.ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(to_fire)))) as pool:
            futs = {pool.submit(_one, c, v): c["id"] for c, v in to_fire}
            for f in _cf.as_completed(futs):
                try: results.append(f.result())
                except Exception as e:
                    results.append({"id": futs[f], "phase": "?", "status": "error", "reason": str(e)[:80]})
    return results
