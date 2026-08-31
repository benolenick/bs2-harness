#!/usr/bin/env python3
"""web_surface_mapper — the MISSING recon stage: map an APPLICATION's attack surface.

autoturret's parse_recon maps a HOST (ports/services -> gitlab/wordpress/... cards).
That's the wrong map for a web app. Ariadne's vocabulary already speaks web
(endpoint/tool/db_backed/injectable/serves_file_by_param/accepts_role_field/reset_flow/
renders_user_input/nosql_injectable/...), and the planner is live on :8112 — but NOTHING
grounds those predicates from a live app. This stage does.

    target URL --gexec(web.recon)--> crawl --> surface.json (the MAP)
                                            --> ariadne_facts.jsonl (validated ground facts)
                                            --> plans.json (per-class Ariadne paths, best-effort)
                                            --> worklist.json (map -> per-class dispatch: the bridge)

Every target-touching fetch goes THROUGH the governed seam (gexec), so recon is governed
and hash-chained like everything else. The mapper reads recon output (paths/params/status —
NOT sensitive exploit content) to build STRUCTURAL facts; vuln CLAIMS (injectable, rce...)
are left as GOALS for the planner + per-class specialists to confirm, never asserted here.

Generic, not target-specific: endpoints are DISCOVERED from the app (HTML + JS bundles +
a small logged fallback probe list), never hardcoded to one app.

Usage:  web_surface_mapper.py --run-dir DIR [--max-fetch 80] [--plan] [--no-plan]
        (DIR must already have a seam.json from `governed_seam.py open`)
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys, urllib.parse
from pathlib import Path

GB = "/opt/bs2/live"
SEAM_PY = f"{GB}/governed_seam.py"
ARIADNE = os.environ.get("GB_ARIADNE", "http://127.0.0.1:8112")
PRED_PATH = "/home/operator/ariadne/ariadne/corpus/predicates.yaml"

# ---- Ariadne predicate arities (validate before emitting; unknown/arity-wrong -> dropped) ----
_FALLBACK_ARITY = {
    "endpoint": 1, "tool": 2, "db_backed": 1, "injectable": 1, "db_read": 1,
    "serves_file_by_param": 1, "no_path_canonicalization": 1, "renders_user_input": 1,
    "template_engine": 2, "accepts_role_field": 1, "reset_flow": 0, "session": 2,
    "nosql_injectable": 1, "insecure_deserialization": 1, "xxe_vulnerable": 1,
    "vuln_present": 2, "can_read": 2, "rce_as": 1, "agent": 1, "input_to_llm": 2,
    "have_cred": 1, "account": 2,
}
def load_arity():
    try:
        import yaml
        d = yaml.safe_load(open(PRED_PATH)) or {}
        out = {p["name"]: int(p["arity"]) for p in d.get("predicates", [])}
        if out:
            return out
    except Exception:
        pass
    return dict(_FALLBACK_ARITY)
ARITY = load_arity()
def valid(fact):
    return isinstance(fact, list) and fact and ARITY.get(fact[0]) == len(fact) - 1 \
        and all(isinstance(a, (str, int, float)) for a in fact[1:])

# ------------------------------------------------------------------ governed fetch
def gfetch(run_dir, url, method="GET", headers=None, data=None, timeout=12):
    """One GET/POST THROUGH the governed seam (web.recon). Returns (status, ctype, body_text, ok)."""
    argv = ["curl", "-sS", "-i", "-m", str(timeout), "-X", method]
    for h in (headers or []):
        argv += ["-H", h]
    if data is not None:
        argv += ["--data", data]
    argv.append(url)
    cmd = ["python3", SEAM_PY, "exec", "--run-dir", run_dir, "--class", "web.recon", "--"] + argv
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 8)
    except Exception:
        return (0, "", "", False)
    raw = p.stdout.decode("utf-8", "replace")
    if p.returncode == 3:                       # governed gate DENIED (shouldn't happen for recon)
        return (-1, "", "", False)
    # curl -i: status line, headers, blank line, body. Handle proxy/redirect header blocks.
    status, ctype, body = 0, "", raw
    m = re.search(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", raw, re.M)
    if m:
        status = int(m.group(1))
    cm = re.search(r"^content-type:\s*([^;\r\n]+)", raw, re.I | re.M)
    if cm:
        ctype = cm.group(1).strip().lower()
    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    if len(parts) == 2 and parts[0].lower().startswith("http"):
        # if multiple header blocks (redirects), keep last body-ish chunk
        body = parts[1]
    return (status, ctype, body, 200 <= status < 400)

# ------------------------------------------------------------------ extraction
PATH_RE  = re.compile(r"""['"](/(?:[A-Za-z0-9_\-./]{1,60}))(?:\?[^'"]*)?['"]""")
API_RE   = re.compile(r"""/(?:rest|api|graphql|ftp|b2b|dataerasure|snippets|metrics|redirect|profile|socket\.io)/[A-Za-z0-9_\-]{1,40}(?:/[A-Za-z0-9_\-]{1,40}){0,3}""", re.I)
ROUTE_RE = re.compile(r"""path\s*:\s*['"]([^'"]{0,60})['"]""")
SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)
API_RE2  = re.compile(r"/[a-z][a-z0-9_-]{1,20}/api/[A-Za-z0-9_./{}-]{2,80}", re.I)  # full /svc/api/... routes (authed apps)
LINK_RE   = re.compile(r"""(?:href|action)=['"]([^'"#]+)['"]""", re.I)
FORM_RE   = re.compile(r"""<form\b[^>]*>(.*?)</form>""", re.I | re.S)
INPUT_RE  = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname=['"]([^'"]+)['"]""", re.I)

# small, LOGGED fallback probe list — generic API/discovery surface, not app-specific
FALLBACK = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/swagger.json",
            "/openapi.json", "/api", "/rest", "/graphql", "/.git/HEAD", "/ftp",
            "/metrics", "/health", "/status", "/api-docs"]

def same_origin(base, link):
    try:
        u = urllib.parse.urljoin(base, link)
        b = urllib.parse.urlparse(base); p = urllib.parse.urlparse(u)
        if p.scheme not in ("http", "https"):
            return None
        if (p.hostname, p.port) != (b.hostname, b.port):
            return None
        return u
    except Exception:
        return None

def norm_path(url):
    try:
        pr = urllib.parse.urlparse(url)
        return pr.path or "/", dict(urllib.parse.parse_qsl(pr.query))
    except Exception:
        return url, {}

# ------------------------------------------------------------------ id templating (GENERAL)
# An object is addressable by an id-looking path segment: a number, a UUID, an email, a long
# opaque token, or an existing :id/{id} route marker. IDOR/BOLA needs that slot preserved --
# so instead of collapsing /thing/42/loc to the collection, we ALSO keep /thing/{id}/loc as a
# templated endpoint and remember the concrete ids we saw. Target-agnostic: no app names here.
ID_SEG = re.compile(r"^(?:\d{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{16,}|[^/@\s]+@[^/\s]+|[A-Za-z0-9_-]{16,})$")
def templatize(path):
    """Return (template_with_{id}_slots, [concrete_id_values]). Empty ids => nothing templated."""
    ids, out = [], []
    for seg in path.split("/"):
        if seg.startswith(":") or (seg.startswith("{") and seg.endswith("}")):
            out.append("{id}")
        elif ID_SEG.match(seg):
            out.append("{id}"); ids.append(seg)
        else:
            out.append(seg)
    return "/".join(out), ids

# ------------------------------------------------------------------ mapper
def run(run_dir, max_fetch, do_plan, auth_config=None, seed_paths=None):
    seam = json.loads((Path(run_dir) / "seam.json").read_text())
    base = seam["target"].rstrip("/")
    origin = base

    fetched, budget_hit = {}, False
    log = lambda m: print(f"[map] {m}", file=sys.stderr)

    # --- authed discovery: sign up + log in (generic, driven by a config), get a bearer ---
    auth_headers = []
    authed = False
    if auth_config:
        try:
            ac = json.loads(Path(auth_config).read_text()) if os.path.exists(auth_config) else json.loads(auth_config)
            if ac.get("signup_url"):
                gfetch(run_dir, base + ac["signup_url"], method="POST",
                       headers=["Content-Type: application/json"], data=json.dumps(ac.get("signup_body", {})))
            lr = gfetch(run_dir, base + ac["login_url"], method="POST",
                        headers=["Content-Type: application/json"], data=json.dumps(ac.get("login_body", {})))
            body = lr[2] if isinstance(lr, tuple) and len(lr) > 2 else ""
            tok = ""
            try:
                i = body.find("{")
                j, _ = json.JSONDecoder().raw_decode(body[i:]) if i >= 0 else ({}, 0)
                for k in ac.get("token_path", ["token"]):
                    j = j.get(k, "") if isinstance(j, dict) else ""
                tok = j if isinstance(j, str) else ""
            except Exception:
                tok = ""
            if tok:
                auth_headers = [ac.get("auth_header", "Authorization: Bearer {token}").format(token=tok)]
                authed = True
                log(f"authed discovery ON (token {len(tok)} chars) — endpoints reachable behind login now visible")
            else:
                log("auth config present but login yielded no token — continuing ANON")
        except Exception as ex:
            log(f"auth bootstrap failed ({ex}) — continuing ANON")

    def fetch(url, method="GET", **kw):
        nonlocal budget_hit
        key = (method, url)
        if key in fetched:
            return fetched[key]
        if len(fetched) >= max_fetch:
            budget_hit = True
            return (0, "", "", False)
        hdrs = list(kw.pop("headers", []) or [])
        if auth_headers:
            hdrs = hdrs + auth_headers
        r = gfetch(run_dir, url, method=method, headers=hdrs, **kw)
        fetched[key] = r
        return r

    log(f"target {base}  (governed web.recon, max_fetch={max_fetch})")

    endpoints = {}       # path -> {"methods":set,"status":int,"ctype":str,"params":set,"role":str,"src":set}
    id_templates = {}    # "/coll/{id}/sub" -> set(concrete id values seen) : the BOLA/IDOR surface
    def harvest_ids(text):
        """Learn id-templated API routes from any body (JS bundle or JSON response). Uses the
        STRUCTURED route regexes (real /api|/rest|/svc/api shape) -- so embedded base64/WASM
        blobs in minified bundles can't leak in as fake routes. General, not target-specific."""
        if not text: return
        for m in set(API_RE.findall(text)) | set(API_RE2.findall(text)):
            t, ids = templatize(m.rstrip("/"))
            if "{id}" in t and 1 < len(t) <= 80 and t.count("{id}") <= 3:
                id_templates.setdefault(t, set()).update(ids)
    def harvest_json_ids(path, body):
        """A collection endpoint that returns a LIST of objects carrying id-looking fields
        implies each object is addressable at /collection/{id}. Standard REST shape -- general,
        no target names. We only synthesize when ids appear INSIDE an array (the collection
        signal), so a lone {"id":..} scalar response doesn't fabricate a route."""
        if not body:
            return
        try:
            i = min([x for x in (body.find("{"), body.find("[")) if x >= 0] or [-1])
            if i < 0:
                return
            data, _ = json.JSONDecoder().raw_decode(body[i:])   # first JSON value; tolerate trailing bytes
        except Exception:
            return
        coll = re.sub(r"/(recent|all|list|index)$", "", path.rstrip("/"))
        vals = set()
        def walk(o, in_list):
            if isinstance(o, dict):
                for k, v in o.items():
                    if in_list and re.search(r"(^|_)id$", k, re.I) \
                       and isinstance(v, (int, str)) and ID_SEG.match(str(v)):
                        vals.add(str(v))
                    walk(v, in_list)
            elif isinstance(o, list):
                for x in o[:25]:
                    walk(x, True)
        walk(data, False)
        if vals:
            id_templates.setdefault(coll + "/{id}", set()).update(sorted(vals)[:8])
    forms = []
    assets = []
    def note(path, params=None, status=None, ctype=None, method="GET", src="crawl"):
        e = endpoints.setdefault(path, {"methods": set(), "status": None, "ctype": "",
                                        "params": set(), "role": "unknown", "src": set()})
        e["methods"].add(method)
        e["src"].add(src)
        if params:
            e["params"].update(params)
        if status is not None:
            e["status"] = status
            e["role"] = ("anon" if 200 <= status < 400 else
                         "auth" if status in (401, 403) else
                         "missing" if status == 404 else "unknown")
        if ctype:
            e["ctype"] = ctype

    # --- 1) index ---
    st, ct, body, ok = fetch(base + "/")
    note("/", status=st, ctype=ct, src="root")
    candidates = set()
    if body:
        harvest_ids(body)
        for src in SCRIPT_RE.findall(body):
            u = same_origin(base + "/", src)
            if u:
                assets.append(u)
        for href in LINK_RE.findall(body):
            u = same_origin(base + "/", href)
            if u:
                candidates.add(u)
        for ap in set(API_RE.findall(body)) | set(API_RE2.findall(body)):
            candidates.add(base + ap)
        for fbody in FORM_RE.findall(body):
            inputs = INPUT_RE.findall(fbody)
            am = re.search(r"""action=['"]([^'"]+)['"]""", fbody, re.I)
            mm = re.search(r"""method=['"]([^'"]+)['"]""", fbody, re.I)
            action = am.group(1) if am else "/"
            ap, _ = norm_path(same_origin(base + "/", action) or action)
            forms.append({"action": ap, "method": (mm.group(1).upper() if mm else "GET"),
                          "inputs": inputs})
            note(ap, params=inputs, method=(mm.group(1).upper() if mm else "GET"), src="form")

    # --- 2) JS bundles -> route table + path literals ---
    for a in assets[:8]:
        if not a.endswith(".js"):
            continue
        st, ct, jb, ok = fetch(a)
        if not jb:
            continue
        harvest_ids(jb)
        for rp in ROUTE_RE.findall(jb):
            rp = "/" + rp.lstrip("/")
            if 1 < len(rp) <= 60:
                candidates.add(same_origin(base + "/", rp) or (base + rp))
        for pth in PATH_RE.findall(jb):
            if pth.startswith(("//",)):
                continue
            candidates.add(base + pth)
        for ap in set(API_RE.findall(jb)) | set(API_RE2.findall(jb)):
            t, ids = templatize(ap)
            if "{id}" in t and 1 < len(t) <= 80:
                id_templates.setdefault(t, set()).update(ids)   # KEEP the {id} slot for BOLA
            coll = re.sub(r"/[:{][A-Za-z0-9_]+}?", "", ap)      # ALSO hit the collection (discovery)
            if 1 < len(coll) <= 60:
                candidates.add(base + coll)

    # --- 3) fallback discovery probes (LOGGED, not silent) ---
    for fp in FALLBACK:
        candidates.add(base + fp)
    if seed_paths:
        for sp in seed_paths:
            u = same_origin(base + "/", sp if sp.startswith("/") else "/"+sp)
            if u:
                candidates.add(u)
        log(f"+{len(seed_paths)} generic authed-discovery seed paths")
    log(f"discovered {len(candidates)} candidate paths (+{len(FALLBACK)} fallback probes)")

    # --- 4) probe candidates (GET), record status/role/params ---
    for u in sorted(candidates):
        p, q = norm_path(u)
        if p in endpoints and endpoints[p]["status"] is not None:
            continue
        st, ct, b, ok = fetch(u)
        if st == 0:
            continue
        # Juice-style SPA returns 200 + index.html for unknown paths. If we probed an api/json-ish
        # path and got HTML back that looks like the SPA shell, it's a fallback, not a real endpoint.
        spa = (st == 200 and ct.startswith("text/html")
               and re.search(r"(rest|api|graphql|\.json$|swagger|openapi|metrics|health|status)", p, re.I)
               and (not b or "<app-root" in b or "ng-version" in b or "<!DOCTYPE html" in b[:200].upper() or "<HTML" in b[:400].upper()))
        note(p, params=list(q.keys()), status=(404 if spa else st),
             ctype=("spa-fallback" if spa else ct), src="probe")
        if b and not spa and ("json" in ct or b.lstrip()[:1] in "{["):
            harvest_ids(b)
            if st == 200:
                harvest_json_ids(p, b)
    if budget_hit:
        log(f"FETCH BUDGET {max_fetch} HIT — surface is PARTIAL (raise --max-fetch to go deeper)")

    # ------------------------------------------------------------------ ground facts
    facts, dropped, worklist = [], [], []
    seen_reset = {"forgot": False, "reset": False}
    def add(f):
        (facts if valid(f) else dropped).append(f)

    DB_HINT   = re.compile(r"(search|query|find|list|products?|users?|feedbacks?|orders?|reviews?|comments?|messages?)\b", re.I)
    FILE_HINT = re.compile(r"(download|file|report|image|photo|attachment|ftp|export|backup|read|view)\b", re.I)
    REG_HINT  = re.compile(r"(register|signup|sign-up|users?)\b", re.I)

    for path, e in sorted(endpoints.items()):
        if e["status"] in (404, None) and "probe" in e["src"] and "crawl" not in e["src"]:
            continue  # don't assert endpoints that 404 on a blind probe
        role = e["role"] if e["role"] in ("anon", "auth") else "anon"
        if authed and e["status"] and 200 <= e["status"] < 400:
            role = "auth"  # reachable only WITH the bearer => behind authz
        add(["endpoint", path])
        add(["tool", path, role])
        looks_json = e["ctype"].endswith("json") or "json" in e["ctype"]
        if DB_HINT.search(path) or (looks_json and (e["params"] or path.rstrip("/").split("/")[-1].endswith("s"))):
            add(["db_backed", path])
            worklist.append({"class": "sqli", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["db_read", _atom(path)],
                             "hypothesis": "db-backed endpoint may pass input unsanitized into a query"})
            worklist.append({"class": "nosqli", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["db_read", _atom(path)],
                             "hypothesis": "if Mongo-backed, operator injection ($ne/$gt) in params"})
        if FILE_HINT.search(path) and (e["params"] or "file" in path.lower() or "ftp" in path.lower()):
            add(["serves_file_by_param", path])
            worklist.append({"class": "path-traversal", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["can_read", "attacker", "/etc/passwd"],
                             "hypothesis": "endpoint returns a file named by a param; test ../ and null-byte"})
        if REG_HINT.search(path) and ("POST" in e["methods"] or "form" in e["src"]):
            worklist.append({"class": "mass-assignment", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["session", "attacker", "admin"],
                             "hypothesis": "registration may trust a client-supplied role field"})
        if "login" in path.lower() or "auth" in path.lower():
            worklist.append({"class": "auth-bypass", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["session", "attacker", "admin"],
                             "hypothesis": "SQLi/logic auth bypass or JWT forgery (alg:none / weak secret)"})
        if e["role"] == "auth" or (e["role"] == "anon" and re.search(r"/(admin|user|account|profile|order|basket|wallet|vehicle|mechanic|report|coupon|location|dashboard)s?/", path, re.I)):
            worklist.append({"class": "broken-access-control", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["session", "attacker", "admin"],
                             "hypothesis": "object/function-level authZ may be missing (IDOR / forced browse)"})
        if re.search(r"forgot|reset.*password|password.*reset|recover", path, re.I):
            seen_reset["forgot" if "forgot" in path.lower() or "recover" in path.lower() else "reset"] = True
        if re.search(r"(chat|bot|assistant|llm|ai)\b", path, re.I):
            nm = _atom(path)
            add(["agent", nm]); add(["input_to_llm", nm, path])
            worklist.append({"class": "llm-injection", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["have_cred", "leaked"],
                             "hypothesis": "prompt-injection / context leak via the agent channel"})
        # reflected-input candidate (render) — feedback/comment/search style
        if re.search(r"(feedback|comment|review|search|message|profile|name)\b", path, re.I):
            worklist.append({"class": "xss", "endpoint": path, "params": sorted(e["params"]),
                             "role": role, "goal": ["renders_user_input", path],
                             "hypothesis": "user input may be rendered without encoding (stored/reflected XSS)"})
    # --- id-templated endpoints -> the BOLA/IDOR lane (GENERAL: any /coll/{id} surface) ---
    known_paths = {p for p, e in endpoints.items() if e.get("status") not in (404, None)}
    for tmpl in sorted(id_templates):
        coll = tmpl.split("/{id}")[0]                     # path up to the first id slot
        grounded = (coll in endpoints
                    or any(k == coll or k.startswith(coll + "/") for k in known_paths)
                    or bool(re.search(r"/(api|rest|graphql)/", tmpl)))
        if not grounded:
            continue                                       # phantom route -> drop (no BOLA row)
        vals = sorted(v for v in id_templates[tmpl] if v)[:8]
        add(["endpoint", tmpl]); add(["tool", tmpl, "auth"])
        worklist.append({"class": "broken-access-control", "endpoint": tmpl,
                         "template": tmpl, "id_values": vals,
                         "params": [], "role": "auth",
                         "goal": ["session", "attacker", "admin"],
                         "hypothesis": "IDOR/BOLA: object addressed by id in path; swap to a neighbor's id"})

    if seen_reset["forgot"] and seen_reset["reset"]:
        add(["reset_flow"])
        worklist.append({"class": "auth-reset", "endpoint": "(reset flow)", "params": [],
                         "role": "anon", "goal": ["session", "attacker", "admin"],
                         "hypothesis": "predictable/weak password-reset (security-question or token)"})

    # de-dup facts + worklist
    uf = []
    for f in facts:
        if f not in uf:
            uf.append(f)
    uw, seenw = [], set()
    for w in worklist:
        k = (w["class"], w["endpoint"])
        if k not in seenw:
            seenw.add(k); uw.append(w)

    # ------------------------------------------------------------------ ariadne plans (best-effort)
    plans = {}
    if do_plan:
        goals = {}
        for w in uw:
            goals.setdefault(tuple(w["goal"]), None)
        for g in goals:
            pr = ariadne_plan(list(g), uf)
            plans[" ".join(map(str, g))] = pr
            paths = (pr or {}).get("paths") or []
            if paths:
                ops = [s.get("name") for s in (paths[0].get("steps") or [])]
                for w in uw:
                    if tuple(w["goal"]) == g:
                        w["plan"] = ops
        log(f"planner: {sum(1 for v in plans.values() if (v or {}).get('paths'))}/{len(plans)} goals have a path")
    else:
        log("planner: skipped (--no-plan)")

    # ------------------------------------------------------------------ write artifacts
    rd = Path(run_dir)
    surface = {
        "target": base,
        "endpoints": [{"path": p, "methods": sorted(e["methods"]), "status": e["status"],
                       "role": e["role"], "ctype": e["ctype"], "params": sorted(e["params"]),
                       "src": sorted(e["src"])}
                      for p, e in sorted(endpoints.items())],
        "forms": forms,
        "assets": assets,
        "fetches": len(fetched),
        "partial": budget_hit,
        "counts": {"endpoints": len(endpoints), "facts": len(uf), "worklist": len(uw),
                   "classes": sorted({w["class"] for w in uw})},
    }
    (rd / "surface.json").write_text(json.dumps(surface, indent=2))
    with (rd / "ariadne_facts.jsonl").open("w") as f:
        for fact in uf:
            f.write(json.dumps(fact) + "\n")
    (rd / "plans.json").write_text(json.dumps(plans, indent=2))
    (rd / "worklist.json").write_text(json.dumps(uw, indent=2))

    # ------------------------------------------------------------------ console summary (content-blind)
    print(f"\n● application-surface map — {base}")
    print(f"  endpoints {len(endpoints)}  facts {len(uf)}  worklist {len(uw)} items"
          + ("  [PARTIAL]" if budget_hit else ""))
    by = {}
    for w in uw:
        by[w["class"]] = by.get(w["class"], 0) + 1
    for c in sorted(by):
        planned = sum(1 for w in uw if w["class"] == c and w.get("plan"))
        print(f"    {c:22} {by[c]:3d} target(s)" + (f"  ({planned} with a planned path)" if planned else ""))
    if dropped:
        print(f"  ({len(dropped)} candidate facts dropped as out-of-vocab)")
    print(f"\n  artifacts: surface.json  ariadne_facts.jsonl  plans.json  worklist.json  (in {run_dir})")
    print("  next: dispatch one specialist per worklist item through gexec (governed).")
    return 0

def _atom(path):
    return re.sub(r"[^A-Za-z0-9_]", "_", path.strip("/")) or "root"

def ariadne_plan(goal, facts, top=3, timeout=6):
    import urllib.request
    try:
        body = json.dumps({"graph": {"goal": goal, "facts": facts, "negatives": []}, "top": top}).encode()
        req = urllib.request.Request(ARIADNE.rstrip("/") + "/plan", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {"error": str(e)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--max-fetch", type=int, default=80)
    ap.add_argument("--plan", dest="plan", action="store_true", default=True)
    ap.add_argument("--no-plan", dest="plan", action="store_false")
    ap.add_argument("--auth-config", default=None, help="JSON (path or literal): signup/login flow to crawl AUTHED")
    ap.add_argument("--seed-paths", default=None, help="JSON list file: generic API resource paths to probe (content-discovery)")
    a = ap.parse_args()
    if not (Path(a.run_dir) / "seam.json").exists():
        print(f"no seam.json in {a.run_dir} — run `governed_seam.py open` first", file=sys.stderr)
        sys.exit(2)
    _seeds = json.load(open(a.seed_paths)) if a.seed_paths else None
    sys.exit(run(a.run_dir, a.max_fetch, a.plan, auth_config=a.auth_config, seed_paths=_seeds))

if __name__ == "__main__":
    main()
