#!/usr/bin/env python3
"""gunbelt AUTOTURRET — the NORTH-STAR engine (backend). See docs/NORTH-STAR.md.

Fuses the two proven halves and adds the missing spine:
  - autocannon's BREADTH belt (build_belt) + recipe-first firing (recipes.py / trooper.py)
  - closer's GROUNDED gate (a compromise fact advances the chain only if backed by real output)
  - an EVENT-DRIVEN scheduler: the instant ONE lane lands a grounded fact, its dependent lanes
    fire IMMEDIATELY — no round barrier (the behavioral change vs autocannon.py)
  - Ariadne re-plan/arming: an un-recipe'd app hands the trooper CVE-matched leads (:8112/exploits)
  - terminates on OWNED (grounded flag / dc_owned) or a PROVABLY DRY frontier, TTL-bounded (minutes)

Output: run/autoturret.jsonl (metadata feed, War-Room schema) + run/lanes.json (grid) +
        run/recon.json (the grounded fact-chain WITH PROVENANCE — the 'winning streams become
        recon' deliverable: the only facts the system proved, and which lane proved each).

Manager/engine/trooper boundary preserved: the ENGINE reads raw output only to GROUND facts;
the feed + recon.json carry metadata + short evidence only, so a content-blind manager reads them.
"""
import argparse, concurrent.futures as cf, json, os, re, sys, threading, time
import urllib.request, urllib.parse
import trooper as T
import recipes as R
from autocannon import build_belt, parse_recon, DOMAIN   # reuse the proven belt DAG + recon parse

RUN_DIR = os.environ.get("AUTOTURRET_RUN", "/opt/bs2/run")
CAP     = int(os.environ.get("AUTOTURRET_CAP", "8"))       # concurrent lanes
TTL     = int(os.environ.get("AUTOTURRET_TTL", "600"))     # seconds — the 'minutes' bound
ARIADNE = os.environ.get("GB_ARIADNE", "http://127.0.0.1:8112")
MEMORIA_SSH = os.environ.get("GB_MEMORIA_SSH", "")               # e.g. "your-host"; empty = Memoria off
MEMORIA_URL = os.environ.get("GB_MEMORIA_URL", "http://127.0.0.1:8009/search")
MANAGER_DIRECTIVES = os.environ.get("GB_MANAGER_DIRECTIVES", "")  # LEVER 3: abstract manager->trooper strategy file
# telemetry tiering: sensitive fact keys are surfaced to the manager as KEY+count only (never value);
# everything else (app/version/vhost/service/port/os/tech) is manager-safe to surface by value.
SENSITIVE_KEYS = {"flag","cred","dc_cred","hash","ntlm","secret","secret_key_base","token","password","pass","key","priv","ssh_key"}

_lock = threading.Lock()
# Two-channel feed (see mailbox 2026-08-21-gunbelt-10-MANAGER-CHANNEL-SCRUB-PATCH):
#   MGR_FEED (canonical autoturret.jsonl) — manager/Opus-safe: labels + fact KEYS + counts, NEVER
#     exploit-objective prose, evidence values, or fact values. A content-blind manager tails THIS.
#   OPS_FEED (autoturret.ops.jsonl) — operator/browser only: objectives + evidence + fact values.
MGR_FEED = "autoturret.jsonl"
OPS_FEED = "autoturret.ops.jsonl"

def _write(fname, row):
    os.makedirs(RUN_DIR, exist_ok=True)
    with _lock:
        with open(os.path.join(RUN_DIR, fname), "a") as f:
            f.write(json.dumps(row) + "\n")

def _row(kind, tool, text, lane, phase):
    return {"ts": int(time.time()), "kind": kind, "tool": tool, "text": str(text)[:400],
            "lane": lane, "phase": phase}

def emit(kind, tool, text, lane="", phase=""):
    """Already-neutral rows (sys/plan/frontier/counts) — written to BOTH feeds."""
    r = _row(kind, tool, text, lane, phase)
    _write(MGR_FEED, r); _write(OPS_FEED, r)

def _failure_class(out, evidence=""):
    """Deterministic failure categoriser. Engine-tier code (may read raw) that returns ONLY a
    safe category label for the MANAGER feed — never raw output. Tells the manager WHICH lever
    to pull without seeing exploit text. Order matters (most specific first)."""
    t = ((out or "") + " " + (evidence or "")).lower()
    if not t.strip():                                    return "no-output"
    if "connection refused" in t or "econnrefused" in t: return "conn-refused"
    if "timed out" in t or "timeout" in t:               return "timeout"
    if "could not resolve" in t or "name or service not known" in t or "no such host" in t: return "dns-fail"
    if "no route to host" in t or "network is unreachable" in t: return "net-unreachable"
    if "401" in t or "unauthorized" in t or "authentication required" in t or "login required" in t: return "auth-required"
    if "403" in t or "forbidden" in t:                   return "http-403"
    if "404" in t or "not found" in t:                   return "http-404"
    if "appears to be safe" in t or "not vulnerable" in t or "target is not exploitable" in t or "check failed" in t: return "check-not-vulnerable"
    if "session" in t and ("no session" in t or "not created" in t or "died" in t or "expired" in t): return "no-session(bind?egress?)"
    if "exploit completed, but no session" in t:         return "no-session(bind?egress?)"
    if "refused to connect" in t or "handler failed to bind" in t: return "bind-failed"
    if re.search(r"\b5\d\d\b", t) and "http" in t:      return "http-5xx"
    if "200" in t:                                        return "http-200-no-proof"
    if "error" in t or "traceback" in t or "exception" in t: return "tool-error"
    return "no-proof"


def emit_split(kind, tool, mgr_label, ops_text, lane="", phase=""):
    """Sensitive rows: scrubbed label -> manager feed, full text -> operator feed only."""
    _write(MGR_FEED, _row(kind, tool, mgr_label, lane, phase))
    _write(OPS_FEED, _row(kind, tool, ops_text, lane, phase))

# ---- manager telemetry: the trooper distills, the engine scrubs (belt-and-suspenders) + serves
_SCRUB = [
    (re.compile(r'(?:HTB|FLAG)\{[^}]*\}', re.I), '<flag>'),
    (re.compile(r'\$(?:P|H|apr1|1|2[aby]|5|6)\$[^\s"\']+'), '<hash>'),
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), '<hex>'),
    (re.compile(r'((?:pass(?:word)?|pwd|token|secret|key|ntlm|hash|priv)\s*[=:]\s*)(\S+)', re.I), r'\1<redacted>'),
]
def _scrub_telemetry(text):
    """Deterministic secret-redaction over the trooper's distilled telemetry. Belt-and-suspenders
    over the model's own '<captured>' rule: even if flash leaks a secret VALUE, it never reaches
    the manager feed. Content-tier code that RETURNS manager-safe text."""
    t = str(text or "")
    for pat, repl in _SCRUB:
        t = pat.sub(repl, t)
    return t.strip()[:400]

def _write_telemetry(entry):
    """Append a manager-safe distilled telemetry entry to atrun/telemetry_feed.json (rolling,
    last 80) — the structured surface the BS2 manager panel reads. Entry MUST be pre-scrubbed."""
    path = os.path.join(RUN_DIR, "telemetry_feed.json")
    with _lock:
        try:
            cur = json.load(open(path)) if os.path.exists(path) else []
        except Exception:
            cur = []
        cur.append(entry); cur = cur[-80:]
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cur, f, indent=2)
        os.replace(tmp, path)

def save_raw(lane, out):
    d = os.path.join(RUN_DIR, "raw"); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, re.sub(r"[^a-zA-Z0-9_-]", "_", lane) + ".txt"), "a") as f:
        f.write((out or "") + "\n" + "=" * 60 + "\n")

# ------------------------------------------------------------------ GROUNDING
# UNLOCK #1 (see NORTH-STAR). A self-reported LLM fact is NOT proof. A compromise-grade fact
# advances the chain only if its value literally appears in this lane's captured output. This is
# the .205 fabrication guard: cred=root:Sup3RS3cuR3@123 asserted with zero output is REJECTED.
FLAG_RE = re.compile(r"^(?:HTB|FLAG)\{[ -~]{4,78}\}$", re.I)
def valid_flag(v):
    return bool(FLAG_RE.match(v.strip()))

def grounded(fact, output):
    """Is `fact` backed by real captured `output`? Deterministic; no model in the hot path."""
    ev = output or ""
    key, _, val = fact.partition("=")
    if key == "shell":                         # code-exec proof: a real id/uid token
        return bool(re.search(r"uid=\d+\(", ev))
    if key in ("cred", "dc_cred"):             # the secret itself must appear in output
        pw = val.split(":", 1)[1] if ":" in val else val
        return bool(pw) and (pw in ev or val in ev)
    if key == "hash":
        return bool(val) and val in ev
    if key == "flag":
        return valid_flag(val)                 # entropy/shape oracle
    return True                                # app=/vhost=/share=/user= are SIGNALS, not proofs

# compromise-grade fact keys must be grounded before their `gives` key unlocks the chain.
COMPROMISE = {"shell", "cred", "dc_cred", "hash", "flag", "dc_owned"}

# ------------------------------------------------------------------ ENGINE
class Autoturret:
    def __init__(self, target, dial="full"):
        self.target = target; self.dial = dial
        self.bind = {}; self.apps = {}; self.arm = {}
        self.facts = set()                     # unlocked KEYS (drives eligibility: needs <= facts)
        self.proven = []                       # [{fact, lane, evidence}] — grounded, with provenance
        self.secrets = {}                      # PRIVATE value channel (session tokens etc.) — fills
        #                                        downstream {{vars}}; never logged / never on the panel
        self.started = set(); self.done = 0; self.hits = 0
        self.owned = False; self.flags = []
        self.tp = T.Trooper(); self.rx = R.Recipes(target)
        self.belt = []

    # -------- arming: hand un-recipe'd footholds CVE-matched leads from Ariadne (best-effort)
    def _ariadne_exploits(self, app, n=4):
        if not app: return ""
        try:
            url = ARIADNE.rstrip("/") + "/exploits?q=" + urllib.parse.quote(app)
            with urllib.request.urlopen(url, timeout=4) as r:
                data = json.load(r)
        except Exception:
            return ""                          # SIGIL: Ariadne is fragile — NEVER blocks the loop
        out = []
        for m in (data.get("matches") or [])[:n]:
            cves = ",".join(m.get("cves") or []) or "no-CVE"
            out.append(f"- EDB-{m.get('edb')}: {m.get('title')} ({cves})")
        return ("\nKNOWN EXPLOITS (Ariadne index — prefer the version-matched one, fetch with "
                "`searchsploit -m <edb>`; never run blind):\n" + "\n".join(out)) if out else ""

    # -------- arming: hand the trooper Memoria RAG technique/exploit hints (best-effort, fail-soft)
    def _memoria_hints(self, app, n=3):
        if not app or not MEMORIA_SSH: return ""
        import subprocess, shlex
        body = json.dumps({"query": f"{app} remote code execution exploit foothold privilege escalation",
                           "limit": n})
        remote = (f"curl -s -m 6 -X POST {shlex.quote(MEMORIA_URL)} "
                  f"-H 'Content-Type: application/json' -d {shlex.quote(body)}")
        try:
            p = subprocess.run(["ssh", "-o", "ConnectTimeout=6", MEMORIA_SSH, remote],
                               capture_output=True, text=True, timeout=14)
            data = json.loads(p.stdout or "{}")
        except Exception:
            return ""                          # SIGIL: Memoria is fragile — NEVER blocks the loop
        out = []
        for r in (data.get("results") or [])[:n]:
            t = " ".join((r.get("text") or "").split())[:180]
            if t: out.append(f"- {t}")
        return ("\nMEMORIA HINTS (RAG corpus — techniques/exploits seen for this service; "
                "adapt to the target, verify before trusting):\n" + "\n".join(out)) if out else ""

    def _fill(self, objective):
        o = (objective.replace("{gitlab_host}", self._host("gitlab"))
                      .replace("{wp_host}", self._host("wordpress"))
                      .replace("{drupal_host}", self._host("drupal")))
        for app, leads in self.arm.items():
            if app in objective.lower() and leads:
                o += leads
        o += self._manager_directives()
        return o

    def _manager_directives(self):
        """LEVER 3 — abstract, content-blind manager guidance injected into EVERY trooper
        objective. The manager writes tool/technique STRATEGY (public knowledge + scrubbed
        facts) here at run time; the trooper picks the concrete commands. Fail-soft; empty
        by default so behaviour is unchanged until the manager writes the file."""
        try:
            p = MANAGER_DIRECTIVES or os.path.join(RUN_DIR, "manager_directives.md")
            if p and os.path.exists(p):
                txt = open(p, errors="ignore").read().strip()
                if txt:
                    return ("\n\nMANAGER DIRECTIVES (standing orders from your commander — "
                            "abstract strategy; obey the intent, YOU choose the exact "
                            "tools/commands/flags):\n" + txt)
        except Exception:
            pass
        return ""

    def _host(self, app):
        v = self.apps.get(app, "")
        return v if (v and not v.isdigit()) else f"{app}.{DOMAIN}"

    # -------- one shot: recipe-first, trooper fallback (identical policy to autocannon)
    def fire(self, lane):
        obj = self._fill(lane["objective"])
        rv = self.rx.fire(lane)
        if rv is not None:
            src = "recipe"; emit("cmd", lane["tool"], f"▶ {lane['id']} [recipe]", lane["id"], lane["phase"])
            v = rv
        else:
            src = "trooper"; emit_split("cmd", lane["tool"], f"▶ {lane['id']} firing", f"▶ {lane['id']}: {obj[:120]}", lane["id"], lane["phase"])
            v = self.tp.fire({"id": lane["id"], "target": self.target, "objective": obj})
        v["_src"] = src
        return lane, v

    def newly_eligible(self):
        return [l for l in self.belt if l["id"] not in self.started and l["needs"] <= self.facts]

    # -------- apply: GROUND facts, unlock keys, arm Ariadne, detect ownership
    def apply(self, lane, v):
        self.done += 1
        out = v.get("output", "")
        save_raw(lane["id"], out)
        ok = bool(v.get("success"))
        self.hits += ok
        src = v.get("_src", "?")
        fcls = "" if ok else _failure_class(out, v.get("evidence", ""))
        mgr_out = f"{'✔ HIT' if ok else '✘ miss'} [{src}]" + (f" ({fcls})" if fcls else "")
        emit_split("out", lane["tool"], mgr_out,
                   f"{'✔ HIT' if ok else '✘ miss'} [{src}] — {v.get('evidence','')}",
                   lane["id"], lane["phase"])

        # TROOPER-DISTILLED TELEMETRY — the trooper saw everything and distilled the tactical
        # picture; the engine scrubs it (belt-and-suspenders) and serves it to the manager. This
        # is the manager's real-time tactile channel: observed / blocked-why / suggested-next.
        tel = v.get("telemetry") or {}
        if tel:
            obs = _scrub_telemetry(tel.get("observed", ""))
            tried = _scrub_telemetry(tel.get("tried", ""))
            blk = _scrub_telemetry(tel.get("blocked", ""))
            nxt = _scrub_telemetry(tel.get("next", ""))
            parts = []
            if obs: parts.append(f"observed: {obs}")
            if blk: parts.append(f"blocked: {blk}")
            if nxt: parts.append(f"next: {nxt}")
            line = " | ".join(parts)[:380]
            if line:
                emit_split("telemetry", lane["tool"], f"◈ {line}", f"◈ {line}", lane["id"], lane["phase"])
            _write_telemetry({"ts": int(time.time()), "src": "trooper", "lane": lane["id"],
                              "phase": lane["phase"], "tool": lane["tool"], "ok": ok, "fclass": fcls,
                              "observed": obs, "tried": tried, "blocked": blk, "next": nxt})

        # recon/enum lanes feed the service binding + app fingerprints (not sensitive content)
        if lane["phase"] in ("recon", "enum"):
            for app, ver in parse_recon(v.get("facts", []), out, self.bind, self.target).items():
                self.apps.setdefault(app, ver)
                key = f"app_{app}"
                if key not in self.facts:
                    self.facts.add(key)
                    leads = self._ariadne_exploits(app)          # UNLOCK #3: arm the foothold
                    mem = self._memoria_hints(app)               # + Memoria RAG hints (double barrel)
                    combined = (leads or "") + (mem or "")
                    if combined: self.arm[app] = combined
                    emit("plan", "engine", f"↳ frontier: {app} staged"
                         f"{' + Ariadne CVE leads' if leads else ''}"
                         f"{' + Memoria hints' if mem else ''}", lane["id"], "frontier")

        # per-fact grounding: only grounded facts are recorded; only grounded compromise facts unlock
        grounded_keys = set()
        for f in v.get("facts", []):
            if "=" not in f: continue
            key = f.split("=", 1)[0].strip().lower()
            if key in COMPROMISE and not grounded(f, out):
                emit_split("plan", "engine", f"⊘ dropped UNGROUNDED {key} (no output backs it)",
                           f"⊘ dropped UNGROUNDED {key} (no output backs it): {f[:60]}",
                           lane["id"], "frontier")
                continue                                         # the .205 fabrication is killed here
            self.proven.append({"fact": f, "lane": lane["id"], "evidence": v.get("evidence", "")[:120]})
            grounded_keys.add(key)
            mgr_fact = f"⚑ {key} (captured)" if key in SENSITIVE_KEYS else f"⚑ {f}"
            emit_split("fact", lane["tool"], mgr_fact, f"⚑ {f}", lane["id"], lane["phase"])
            # A flag is LOOT, not ownership. On a multi-flag box we keep draining the frontier —
            # ownership is a real DC compromise or a root shell (set below), never a recon flag.
            if key == "flag":
                self.flags.append(f.split("=", 1)[1])
                emit("plan", "engine", f"⚑ flag looted ({len(self.flags)}) — keep firing", lane["id"], "loot")
            if key == "shell" and f.split("=", 1)[1].strip() == "root":
                self.owned = True
                emit("plan", "engine", "⚑ ROOT shell proven — OWNED", lane["id"], "own")

        # the lane's declared `gives` key unlocks the chain — but a compromise `gives` needs a
        # grounded fact of that key this lane (structural needs-enforcement: no phantom foothold).
        gives = lane.get("gives")
        if ok and gives and gives not in self.facts:
            if gives in COMPROMISE and gives not in grounded_keys:
                emit("plan", "engine", f"⊘ {lane['id']} 'success' but no grounded {gives} — chain NOT advanced",
                     lane["id"], "frontier")
            else:
                self.facts.add(gives)
                emit("plan", "engine", f"↳ {gives} confirmed (chain advances)", lane["id"], "frontier")
                if gives == "dc_owned": self.owned = True
        # generic signal keys (hash/cred/shell) also unlock their own key when grounded
        for key in grounded_keys:
            if key in ("hash", "cred", "shell") and key not in self.facts:
                self.facts.add(key)
                emit("plan", "engine", f"↳ signal {key} — dependent lanes armed", lane["id"], "frontier")
        self.snapshot()

    def snapshot(self):
        s = {"target": self.target, "owned": self.owned, "facts": sorted(self.facts),
             "apps": self.apps, "fired": self.done, "hits": self.hits,
             "proven": self.proven,
             "lanes": [{"id": l["id"], "phase": l["phase"], "needs": sorted(l["needs"]),
                        "gives": l.get("gives", ""),
                        "state": ("done" if l["id"] in self.started else
                                  ("ready" if l["needs"] <= self.facts else "staged"))}
                       for l in self.belt]}
        with open(os.path.join(RUN_DIR, "lanes.json"), "w") as f:
            json.dump(s, f, indent=2)

    def _resolve_goal(self, goal):
        """CLI goal shorthand -> a concrete Ariadne goal term. 'rce'->foothold on the app user,
        'root'->rce_as(root), 'flag'->read_file(/root/root.txt), or explicit 'pred:arg'."""
        app = next((a for a in ("gitlab", "wordpress", "drupal", "osticket") if a in self.apps), "")
        user = {"gitlab": "git", "wordpress": "www-data", "drupal": "www-data"}.get(app, "www-data")
        if goal == "rce":  return ["rce_as", user]
        if goal == "root": return ["rce_as", "root"]
        if goal == "flag": return ["read_file", "/root/root.txt"]
        if ":" in goal:    return goal.split(":", 1)
        return ["rce_as", user]

    def write_recon(self, reason):
        """The 'winning streams become recon' deliverable — grounded facts + provenance."""
        recon = {"target": self.target, "owned": self.owned, "stopped": reason,
                 "fired": self.done, "hits": self.hits, "flags": self.flags,
                 "proven_facts": self.proven,
                 "apps": self.apps, "unlocked_keys": sorted(self.facts)}
        with open(os.path.join(RUN_DIR, "recon.json"), "w") as f:
            json.dump(recon, f, indent=2)
        return recon

    # -------- CATALOG SWEEP: fire terrain-matched authored cards (deck_final) through the
    # trooper, verify by the gate. Coverage-by-volume: as facts unlock, more cards become
    # eligible, so we re-sweep until dry. Content-blind to the manager (labels + fact KEYS).
    def catalog_sweep(self):
        if os.environ.get("AUTOTURRET_CATALOG", "") not in ("1", "true", "yes"):
            return
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "catalog"))
            import bridge
        except Exception as e:
            emit("plan", "engine", f"catalog sweep unavailable: {e}", "", "plan"); return
        emit("sys", "engine", "CATALOG sweep — firing terrain-matched authored cards", "", "sweep")
        self._review = []                       # handoff worklist: indeterminate + unproven claims
        recon = {"target": self.target, "apps": self.apps, "bind": self.bind,
                 "unlocked_keys": sorted(self.facts),
                 "proven_facts": [{"fact": p["fact"]} for p in self.proven],
                 "_secrets": self.secrets}      # private value channel (kept off recon.json/telemetry)
        # At full dial in an authorized isolated lab, fire the high-blast (needs_gate) exploit/
        # cred/privesc cards too — the success_if GATE is the safety net (junk fails the gate,
        # grounds nothing). At semi/manual, only auto-safe cards fire; the rest queue for approval.
        fire_gated = (self.dial == "full")
        fired = set()
        for rnd in range(4):
            results = bridge.sweep(recon, self.target, T.run_cmd, dial=self.dial,
                                   autofire_only=not fire_gated)
            new = 0
            for r in results:
                if r["id"] in fired or r["status"] in ("needs-gate", "staged"):
                    continue
                fired.add(r["id"]); new += 1; self.done += 1
                st = r["status"]; via = r.get("src", "gate")
                fc = f" [{r.get('fclass')}]" if st == "miss" and r.get("fclass") else ""
                emit_split("out", "catalog", f"card {r['id']}: {st} ({via}){fc}",
                           f"card {r['id']}: {st} ({via}) rc={r.get('rc')}", r["id"], r["phase"])
                # unified manager panel: card verdict + failure-class (msf cards have no trooper
                # telemetry, but the failure-class IS their distilled tactical signal).
                _write_telemetry({"ts": int(time.time()), "src": "catalog", "lane": r["id"],
                                  "phase": r["phase"], "tool": "catalog", "ok": st == "hit",
                                  "fclass": (r.get("fclass") or "") if st == "miss" else "",
                                  "observed": f"card fired via {via}", "tried": r["id"],
                                  "blocked": (r.get("fclass") or "") if st == "miss" else "",
                                  "next": ""})
                if st == "hit":
                    self.hits += 1
                    # collect any captured secret VALUES into the private channel so the next round's
                    # post-auth cards can fill {{token}} etc. Never logged, never grounded as a fact.
                    if r.get("secrets"):
                        self.secrets.update(r["secrets"])
                    for key in r.get("emits", []):
                        if key not in self.facts:
                            self.facts.add(key)
                            self.proven.append({"fact": key, "lane": r["id"],
                                                "evidence": f"{via}-verified"})
                            emit_split("fact", "catalog", f"⚑ {key}",
                                       f"⚑ {key} [{r['id']}]", r["id"], r["phase"])
                            if key == "shell":
                                emit("plan", "engine", "↳ FOOTHOLD grounded (uid= proven)",
                                     r["id"], "frontier")
                    if r.get("root"):
                        self.owned = True
                        emit("plan", "engine", "⚑ ROOT shell proven (uid=0) — OWNED",
                             r["id"], "own")
                    # gate/judge said hit but a compromise emit lacked hard proof -> review, no ground
                    for e in r.get("unproven", []):
                        emit("plan", "engine",
                             f"⚑? {r['id']} claims {e} but no hard proof — flag for review",
                             r["id"], "frontier")
                        self._review.append({"card": r["id"], "phase": r["phase"],
                                             "reason": f"claims {e}, no hard proof", "rc": r.get("rc")})
                elif st == "indeterminate":
                    emit("plan", "engine",
                         f"⚑? {r['id']} gate indeterminate — flag for human/smarter-AI review",
                         r["id"], r["phase"])
                    self._review.append({"card": r["id"], "phase": r["phase"],
                                         "reason": "gate indeterminate (prose/unclear)",
                                         "rc": r.get("rc"), "gate": r.get("gate", ""),
                                         "raw": f"raw/{r['id']}.txt"})
            if new == 0:
                break
            recon["unlocked_keys"] = sorted(self.facts)
        # the handoff artifact: a worklist of what the machine could NOT verify autonomously,
        # for a human / smarter-AI to advise on (raw pointers are read by THEM, never the manager).
        with open(os.path.join(RUN_DIR, "review_queue.json"), "w") as f:
            json.dump({"target": self.target, "count": len(self._review),
                       "items": self._review}, f, indent=2)
        emit("sys", "engine", f"CATALOG sweep done — {len(fired)} cards fired, "
             f"{len(self._review)} queued for review", "", "sweep")
        self.snapshot()

    # -------- UNLOCK #2: EVENT-DRIVEN scheduler (rolling as_completed; instant follow-up)
    def run(self, planner_goal=None):
        os.makedirs(RUN_DIR, exist_ok=True)
        open(os.path.join(RUN_DIR, MGR_FEED), "w").close()
        open(os.path.join(RUN_DIR, OPS_FEED), "w").close()
        emit("sys", "engine", f"AUTOTURRET online — target {self.target}, dial={self.dial}, "
             f"trooper={T.MODEL}, ttl={TTL}s", "", "boot")
        self.belt = build_belt(self.target, self.bind)
        # When the PLANNER drives the tail, the belt is FLOOR-ONLY (recon+enum). The planner owns
        # all exploitation, so it isn't front-run by the static belt (NORTH-STAR: belt=floor).
        # (The exploit/loot/etc lanes stay reachable via self._all_lanes for the planner to fire.)
        self._all_lanes = list(self.belt)
        if planner_goal:
            self.belt = [l for l in self.belt if l["phase"] in ("recon", "enum")]
        self.snapshot()
        pool = cf.ThreadPoolExecutor(max_workers=CAP)
        inflight = {}

        def submit_ready():
            for l in self.newly_eligible():
                self.started.add(l["id"])
                inflight[pool.submit(self.fire, l)] = l
            if inflight:
                emit("sys", "engine", f"inflight: {len(inflight)} "
                     f"[{', '.join(inflight[f]['id'] for f in inflight)}]", "", "sched")

        submit_ready()
        deadline = time.time() + TTL
        reason = "frontier dry (genuinely out of ideas)"
        while inflight:
            if time.time() > deadline:
                reason = f"TTL {TTL}s reached"; break
            if self.owned:
                reason = "OWNED"; break
            done, _ = cf.wait(list(inflight), timeout=min(15, max(1, deadline - time.time())),
                              return_when=cf.FIRST_COMPLETED)
            for fut in done:
                lane = inflight.pop(fut)
                try:
                    _, v = fut.result()
                except Exception as e:
                    v = {"success": False, "evidence": f"lane crash: {e}", "facts": [], "output": "", "_src": "?"}
                self.apply(lane, v)
            submit_ready()                       # <-- fire freshly-unlocked lanes THE INSTANT a fact lands

        pool.shutdown(wait=False, cancel_futures=True)

        # CATALOG SWEEP: after the floor grounds recon terrain, fire the authored deck's
        # terrain-matched cards (exploit/cred/privesc coverage-by-volume), gate-verified.
        if not self.owned:
            self.catalog_sweep()

        # UNLOCK #3: after the floor drains, the PLANNER LOOP drives the tail toward a goal —
        # manager-set goal -> Ariadne /plan -> fire operator -> ground -> negative-prune -> re-plan.
        if planner_goal and not self.owned:
            try:
                import autoturret_planner as PL
                g = self._resolve_goal(planner_goal)
                st = PL.plan_and_fire(self, g, emit)
                if st.get("grounded"):
                    reason = f"planner grounded goal {g}"
            except Exception as e:
                emit("plan", "planner", f"planner phase error: {e}", "", "plan")

        recon = self.write_recon(reason)
        emit("sys", "engine", f"run complete [{reason}] — {self.hits}/{self.done} hits, "
             f"owned={self.owned}, {len(self.flags)} flags, {len(self.proven)} grounded facts", "", "done")
        return recon


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--dial", default="full", choices=["manual", "semi", "full"])
    ap.add_argument("--run-dir", default=RUN_DIR)
    ap.add_argument("--ttl", type=int, default=TTL)
    ap.add_argument("--planner", metavar="GOAL", default=None,
                    help="run the Ariadne planner loop after the floor: rce|root|flag|<pred>:<arg>")
    a = ap.parse_args()
    RUN_DIR = a.run_dir; TTL = a.ttl
    eng = Autoturret(a.target, dial=a.dial)
    recon = eng.run(planner_goal=a.planner)
    print(json.dumps({"owned": recon["owned"], "stopped": recon["stopped"],
                      "fired": recon["fired"], "hits": recon["hits"], "flags": recon["flags"],
                      "grounded_facts": [p["fact"] for p in recon["proven_facts"]],
                      "run_dir": RUN_DIR}, indent=2))
