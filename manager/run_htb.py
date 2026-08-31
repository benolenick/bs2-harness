#!/usr/bin/env python3
"""run_htb — GENERAL manager-in-the-loop driver for ANY target. Nothing hardcoded to a box.

North star (HOW_I_BROKE_BATTLESTATION_AND_HOW_IT_SHOULD_WORK.md): a content-blind MANAGER
(Opus, `claude -p`) is FED a live picture each step — the MAP it has built so far (accumulated
sanitized facts + telemetry), Ariadne's PROPOSED ROUTES (best-effort, if the planner is up),
and Memoria RECALL (corpus hints keyed off what's been observed) — and AUTHORS exactly ONE next
command. The TROOPER (cheap model, trooper.py, scope-guarded) fires that one command and returns
ONLY a sanitized marker: distilled telemetry (services/versions/walls) + scrubbed facts (a flag,
a cred as '<captured>', a shell user). The manager never sees raw output. Loop until a flag /
shell / dead-end or the step cap.

There is NO `if <service>:` / `if <vuln>:` strategy anywhere here. The manager decides every move
live from the picture; this file only (a) assembles the picture and (b) fires the authored command
and scrubs the result. Works on any target because it knows nothing about any target.

  usage:  python3 run_htb.py <target>  [--steps N] [--model deepseek-v4-flash]
"""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

MANAGER = "/opt/bs2/manager"
LIVE    = "/opt/bs2/live"
for p in (MANAGER, LIVE):
    if p not in sys.path: sys.path.insert(0, p)

# ---- trooper (hands) env: HTB target is NOT loopback -> keep the hard loopback deny ----
os.environ.setdefault("TROOPER_BASE",  "https://api.deepseek.com")
os.environ.setdefault("TROOPER_MODEL", os.environ.get("DS_MODEL", "deepseek-v4-flash"))
os.environ.setdefault("TROOPER_KEY_FILE", "/opt/bs2/.ds_key")
os.environ["TROOPER_CMD_TIMEOUT"] = os.environ.get("TROOPER_CMD_TIMEOUT", "90")   # nmap/gobuster need room
os.environ.pop("GB_ALLOW_LOOPBACK", None)                                          # never on for HTB

import trooper as TR
try:
    import memoria_enrich as MEM
except Exception:
    MEM = None
try:
    import recon_advisor as RA          # Ariadne-facing planner (best-effort feed)
except Exception:
    RA = None
try:
    import htb_observations as H         # scrubbed observations -> Ariadne graph facts
except Exception:
    H = None
import cartographer as CG                # durable discovery map + Ariadne grounding
import cartographer.hypotheses as HYP    # deterministic hypothesis bookkeeping only
import cartographer.report as CARTO_REPORT  # offline finding/report assembly
from cartographer.model import UNVERIFIED
import target_exec as TEXEC              # §10.1 single target-contact door (recon ritual too)
from experiment_ledger import ExperimentLedger   # ONE no-repeat ledger per run dir (shared lanes)
import charter                           # canonical loop top: the human-approved Battle Charter
import hands as HANDS                    # canonical hands: owns routine recon (ritual + vhost verify)
from lenz_harness import SafeLenzStream, NullLenz

# durable mirror of run artifacts: a /tmp wipe must not erase the engagement evidence base
DURABLE_DIR = os.environ.get("GB_DURABLE_DIR", "/opt/bs2/runs")

_WELL_KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 139: "smb", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 1433: "mssql", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 27017: "mongodb",
    8000: "http", 8080: "http", 8443: "https",
}


# ---- service-name normalization: any free-form banner string -> a Cartographer RITUALS key ----
_SERVICE_KEYS = {
    "openssh": "ssh", "ssh": "ssh",
    "vsftpd": "ftp", "proftpd": "ftp", "pure-ftpd": "ftp", "ftpd": "ftp",
    "postfix": "smtp", "sendmail": "smtp", "exim": "smtp",
    "apache": "http", "httpd": "http", "nginx": "http", "iis": "http",
    "microsoft-iis": "http", "tomcat": "http", "jetty": "http",
    "lighttpd": "http", "caddy": "http", "werkzeug": "http", "gunicorn": "http",
    "dovecot-pop3": "pop3", "dovecot-imap": "imap", "dovecot": "imap",
    "imap": "imap", "pop3": "pop3",
    "rpcbind": "rpcbind", "portmapper": "rpcbind",
    "dns": "dns", "bind": "dns", "dnsmasq": "dns", "nsd": "dns", "unbound": "dns", "named": "dns",
    "samba": "smb", "smbd": "smb", "microsoft-ds": "smb", "smb": "smb", "netbios": "smb",
    "mysql": "mysql", "mariadb": "mysql",
    "postgres": "postgres", "redis": "redis", "mongodb": "mongodb",
    "microsoft-sql": "mssql", "mssql": "mssql",
    "elasticsearch": "elasticsearch", "jira": "jira", "confluence": "confluence",
    "snmp": "snmp", "nfs": "nfs", "ldap": "ldap", "kerberos": "kerberos", "rdp": "rdp",
}


def _norm_service(name):
    """Map a free-form banner/service string to a Cartographer service key (longest match)."""
    s = str(name or "").strip().lower()
    if not s:
        return "unknown"
    for key in sorted(_SERVICE_KEYS, key=len, reverse=True):
        if key in s:
            return _SERVICE_KEYS[key]
    m = re.match(r"[a-z][a-z0-9._-]*", s)
    return (m.group(0).rstrip(".-") if m else s) or "unknown"


def _split_version(name):
    """Split 'vsftpd3.0.3' / 'Apache httpd 2.4.41' -> (base, version).

    Only a TRAILING digit-run counts as a version, and only when the base left behind
    is free of digits — so 'OpenSSH8.2p1Ubuntu-4ubuntu0.5' stays whole (no fake '0.5')
    and 'Dovecot-pop3s' never splits (the 3 is part of the protocol name)."""
    name = str(name or "").strip()
    m = re.search(r"(\d[\d.]*)$", name)
    if m and not re.search(r"\d", name[:m.start(1)]):
        return (name[:m.start(1)].strip(" .-_") or name, m.group(1))
    return name, ""


_OBS_PORT = re.compile(r"\b(\d{1,5})\s*/\s*([A-Za-z][A-Za-z0-9._-]*)")


def _observed_ports(telemetry):
    """Parse trooper telemetry like '21/vsftpd3.0.3, 22/OpenSSH8.2p1...' -> {port: (base, ver)}."""
    out = {}
    blob = str((telemetry or {}).get("observed") or "")
    for m in _OBS_PORT.finditer(blob):
        port = int(m.group(1))
        if not 1 <= port <= 65535 or port in out:
            continue
        base, ver = _split_version(m.group(2))
        out[port] = (base, ver)
    return out


def _surface_to_mapjson(facts, telemetry, target):
    """Build Cartographer's host/port map from BOTH scrubbed facts AND observed telemetry.

    Root cause of the 'coverage stays 0%' bug: the trooper's richest recon data lives in
    telemetry.observed ('21/vsftpd3.0.3, ...') but only key=value FACTS were parsed, so
    discovered services never became map nodes and the manager re-asked for the same
    enumeration. Every caller of this function must re-ingest when the result changes."""
    ports = {}
    for fact in (facts or []):
        key, sep, value = str(fact).partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if key == "ports":
            for token in re.findall(r"\b\d{1,5}\b", value):
                port = int(token)
                if 1 <= port <= 65535:
                    ports.setdefault(port, {"port": port,
                                            "name": _WELL_KNOWN_SERVICES.get(port, "unknown"),
                                            "product": "", "version": ""})
        else:
            match = re.fullmatch(r"web(\d{1,5})", key)
            if match:
                port = int(match.group(1))
                base, ver = _split_version(value)
                cur = ports.setdefault(port, {"port": port, "name": "http",
                                              "product": value, "version": ver})
                # a ports= fact may have seeded this port first — enrich, don't clobber
                if not cur["product"]:
                    cur["product"] = value
                if not cur["version"] and ver:
                    cur["version"] = ver
    for port, (base, ver) in _observed_ports(telemetry).items():
        svc = _norm_service(base)
        cur = ports.setdefault(port, {"port": port, "name": svc, "product": base, "version": ver})
        if cur["name"] == "unknown" and svc != "unknown":
            cur["name"] = svc
        if not cur["product"] and base:
            cur["product"] = base
        if not cur["version"] and ver:
            cur["version"] = ver
    if not ports:
        return None
    return {"target": target,
            "hosts": [{"ip": target, "ports": sorted(ports.values(), key=lambda p: p["port"])}]}


def _gnmap_ports(text):
    """Extract open ports from nmap grepable output."""
    ports = []
    for line in str(text or "").splitlines():
        if "Ports:" not in line:
            continue
        for m in re.finditer(r"(\d{1,5})/open(?:[|]filtered)?/", line):
            port = int(m.group(1))
            if port not in ports:
                ports.append(port)
    return sorted(ports)


def _gnmap_surface(text, target, fallback_ports=None):
    """Build a surface map from nmap -sV grepable output ('.../open/tcp//ftp//vsftpd 3.0.3/...')."""
    ports = {}
    for line in str(text or "").splitlines():
        if "Ports:" not in line:
            continue
        m = re.search(r"Ports:\s*(.*)", line)
        for ent in (m.group(1) or "").split(","):
            parts = ent.strip().split("/")
            # gnmap entry layout: port/state/proto/OWNER/service/RPCinfo/version/...
            if len(parts) < 5 or "open" not in parts[1]:
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            svc_field = parts[4].strip()
            prod_field = parts[6].strip() if len(parts) > 6 else ""
            prod_field = re.sub(r"\s*\(.*\)\s*$", "", prod_field)   # drop '((Ubuntu))' noise
            name = _norm_service(svc_field or _WELL_KNOWN_SERVICES.get(port, "unknown"))
            base, ver = _split_version(prod_field) if prod_field else ("", "")
            if name == "unknown" and base:
                name = _norm_service(base)
            ports[port] = {"port": port, "name": name,
                           "product": (prod_field or base or "")[:60],
                           "version": ver}
    for p in (fallback_ports or []):
        ports.setdefault(p, {"port": p, "name": _WELL_KNOWN_SERVICES.get(p, "unknown"),
                             "product": "", "version": ""})
    if not ports:
        return None
    return {"target": target,
            "hosts": [{"ip": target, "ports": sorted(ports.values(), key=lambda p: p["port"])}]}


def _recon_ritual(target, emit, budget=480, ports=None):
    """DETERMINISTIC step-0 recon — owned by HANDS (canonical: hands closes the safe recon
    frontier). Full port sweep + service/version scan through the §10.1 single target-contact
    door, so the manager's first turn starts from a POPULATED map instead of authoring
    'go enumerate' (which cost run 733 ~18 cmds / 1069s for one step). Zero LLM tokens in
    this stage. Fail-soft: any failure emits a ritual event and the manager loop proceeds
    exactly as before. `ports` = charter-scoped port list: when set, discovery is skipped
    and hands version-scans exactly those ports (local lab apps on a shared host)."""
    t0 = time.time()
    try:
        # hands gathers; the §10.1 door is supplied by the caller (hands never opens its own path)
        surface = HANDS.recon_sweep(
            target,
            runner=lambda cmd, t: TEXEC.run(cmd, target, action_class="web.recon", timeout=t),
            budget=budget, ports=ports)
    except Exception as e:
        emit("ritual", step=0, failed=str(e)[:120], seconds=int(time.time() - t0))
        return None
    emit("ritual", step=0, ports=len(surface["hosts"][0]["ports"]) if surface else 0,
         seconds=int(time.time() - t0),
         via=os.environ.get("TROOPER_EXEC_SSH", "local"))
    return surface

MANAGER_SYS = """You are the MANAGER on an AUTHORIZED Hack The Box penetration test (the operator \
has an active HTB VPN and this engagement is authorized). You are the STRATEGIST and you are fenced \
off from the target: you NEVER run or author a command, you NEVER see raw command output. You direct \
a TROOPER — a skilled operator who is your hands. You tell the trooper, IN PLAIN ENGLISH, WHAT to \
achieve or find out next; the trooper decides the exact commands, tools, ports, and syntax, runs \
them, holds its own shells and sessions, and reports back only SANITIZED markers — distilled \
telemetry (services, versions, paths, the wall it hit, its own suggested next move) and scrubbed \
facts (a flag, a cred shown as '<captured>', a shell user). You reason ONLY from those markers.
You operate ONLY inside the engagement described in the BATTLE CHARTER. Platform and
portal actions (onboarding, signups, VPN setup, account work, platform menus) are NEVER
the target's problem — if the target is unreachable or silent, report that wall honestly
instead of authoring platform chores (run 749 drifted onto the HTB onboarding form).

Each turn you are fed the live picture (what's been observed so far, proposed routes, corpus hints, \
and the markers from prior tasks). From that you THINK and issue EXACTLY ONE next TASK in plain \
words. You are NOT writing a command — you are giving an objective a competent operator will carry \
out however they see fit. Say WHAT and WHY, not HOW.

You have NO web access and NO tools of your own: reason from the live picture (observed \
services/versions, Ariadne's routes, Memoria's corpus hints, prior markers) — NOT from an open-web \
walkthrough or CVE lookup. If a version looks exploitable, name the technique/CVE in your TASK and \
let the trooper carry it out and report back whether it worked. Output your action as a single verb \
line (nothing else, no markdown), optionally preceded by EXACTLY ONE rationale line of the form \
`WHY: <one sentence: what you concluded from the markers and why this is the next move>`. The WHY \
line is recorded for audit; only the verb line drives the trooper. So your reply is either one line \
(the verb line) or two lines (WHY line, then the verb line) — nothing more:

  TASK <plain-English objective>  -> the trooper works it out, runs whatever it takes, reports back.
  AUTOTURRET               -> clear ALL offered cheap lanes now (your tool; fires only on your word).
  FINDING <short text>    -> record something proven (a flag, a foothold, a cred captured).
  VERDICT <id> <confirmed|rejected|inconclusive>: <one-line reason>
  HYPOTHESIS <vuln_class> @ <node-or-locus>: <title>
  DONE <one-line reason>  -> stop only when the supplied coverage report is COMPLETE.
  DONE FORCE <reason>     -> explicitly stop early despite incomplete coverage (DONE --force also works).

A good TASK names an intent and a target and, when useful, the technique — e.g. "Enumerate all \
web services on the target and identify each app and version", "The GitLab you found looks like \
13.10 — try the CVE-2021-22205 ExifTool RCE against its real vhost and get command execution", \
"You have a shell on the edge host — read its network interfaces and routes and tell me every \
internal subnet and host you can now reach", "Spray the credential you looted across SMB on the \
internal hosts and report where it authenticates". You do NOT specify curl flags, ports, /etc/hosts \
edits, listener setup, or msf options — that is the trooper's craft. Trust it.

How to think (STRATEGY — adapt to what the markers say, this is NOT a checklist):
- Start with the single cheapest discriminating recon; build the map before committing to an attack.
- When a task reveals a service/version, let that steer the next objective — enumerate, then attack \
the specific thing you found, not a generic guess.
- Recognizing a familiar app (osTicket, GitLab, a WordPress theme) tells you the SOFTWARE, NOT the \
hostname or the box. Do NOT invent a hostname ('delivery.htb' because you saw osTicket) and hand it \
to the trooper as fact. If a vhost matters, TASK the trooper to DISCOVER the real hostname from \
evidence (cert SAN, DNS/rDNS, a redirect, an email/link in the page, a vhost fuzz) and use it.
- When the trooper reports a definitive WALL (auth required, patched version, closed port, \
'no session', wrong app), do NOT re-issue the same task — give a DIFFERENT strategic direction. The \
trooper already handled the tactical retries within its task; a wall coming back to you means that \
avenue is spent, so pivot to another service, host, or technique.
- The trooper holds its OWN sessions: once it has a foothold it keeps that shell alive across your \
tasks. So you can say "using the shell you already hold, now do X" and it will — you never have to \
re-establish access you already have.

Observations become durable hypotheses. Validate the ranked open hypotheses by TASKing the trooper \
with bounded objectives, then record a VERDICT; a vulnerability FINDING is a confirmed hypothesis \
with evidence. Do not re-test rejected hypotheses. Seek one proof marker, never data exfiltration. \
You remain the shot-caller over what to pursue and in what order.

OBJECTIVE (staged — full compromise, not a flag hunt; let the MAP, not an assumption, set the ceiling):
Your goal is to fully compromise the target environment — take every reachable host to its highest \
privilege. Do NOT assume the shape of the environment; discover it and let what you find set the \
endgame. Work these milestones and keep going — do NOT stop early:
  1. Get an INTERACTIVE FOOTHOLD SHELL on the external host by exploiting a real service/app \
(a flag file lying in an open share is a NOTE, not the objective — record it with FINDING and \
KEEP GOING; it does not end the engagement).
  2. From the foothold, escalate to the highest local privilege (root/SYSTEM/Administrator), and \
loot credentials (configs, env, DB) and crack any hashes you recover.
  3. Discover the internal network from that foothold (interfaces, routes, reachable hosts). THEN \
let the topology decide:
     - If you uncover a DOMAIN / directory service / additional hosts: treat each discovered host \
as a NEW target, PIVOT (e.g. a chisel tunnel through the foothold), and drive toward the highest \
authority in that environment (e.g. Domain Admin if it is an AD domain).
     - If the target is STANDALONE (no domain, no further reachable hosts): full root/Administrator \
on that host IS the objective — do not invent a domain controller that the map does not show.
Only DONE when every reachable host is at highest privilege and no unexplored pivot remains, or you \
genuinely cannot proceed — and say precisely where you're stuck. Getting one flag is NOT done.

FULL-VISIBILITY UPDATE (overrides the marker-only language above): you now ALSO receive, under
"RAW", the exact commands the trooper ran and a bounded tail of their real output. Use it to
VERIFY, not just trust, what the trooper claims. HARD RULE: do NOT record or act on a foothold /
shell / RCE unless the RAW shows a command the trooper actually ran AGAINST THE TARGET printing a
live id/whoami/uid or a real 'session opened' -- reading uid= inside an exploit-db writeup, a
`searchsploit -x`, or `msfconsole ... show options` is NOT a shell. If the trooper only searched
for or described an exploit without firing it, your next objective is to make it FIRE that exploit
(set the params and run), not to move on. If a prior marker claims a shell the RAW does not prove,
treat that host as still un-footholded and say so."""


def _call_deepseek_manager(prompt, model, timeout):
    """Manager brain on DeepSeek (V4 pro). Full visibility: it reasons from the SAME prompt that
    now carries RAW trooper output. Returns the assistant's final text (content), not reasoning."""
    import urllib.request
    key = ""
    kf = os.environ.get("TROOPER_KEY_FILE", "")
    if os.environ.get("TROOPER_KEY"):
        key = os.environ["TROOPER_KEY"]
    elif kf and os.path.exists(kf):
        key = open(kf).read().strip()
    base = os.environ.get("MANAGER_BASE", os.environ.get("TROOPER_BASE", "https://api.deepseek.com"))
    hdr = {"Content-Type": "application/json"}
    if key:
        hdr["Authorization"] = "Bearer " + key
    body = json.dumps({"model": model,
                       "messages": [{"role": "system", "content": MANAGER_SYS},
                                    {"role": "user", "content": prompt}],
                       "temperature": 0,
                       "max_tokens": int(os.environ.get("MANAGER_MAX_TOKENS", "8000")),
                       "stream": False}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions", body, hdr)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        msg = json.load(r)["choices"][0]["message"]
    content = (msg.get("content") or "").strip()
    if content:
        return content
    # Reasoning model spent its whole budget thinking and returned empty content: salvage the
    # decision from the reasoning trace by pulling the LAST action-shaped line it wrote.
    rc = (msg.get("reasoning_content") or "")
    for ln in reversed(rc.splitlines()):
        if re.match(r"\s*(TASK|FINDING|VERDICT|HYPOTHESIS|DONE|AUTOTURRET)\b", ln):
            return ln.strip()
    return ""


def call_manager(prompt, model="deepseek-v4-pro", timeout=260.0):
    """Manager brain. DeepSeek (default, full-visibility) for deepseek-* models; else headless
    content-blind claude -p (legacy). Authors one action line; runs nothing itself either way."""
    if str(model).startswith("deepseek"):
        try:
            return _call_deepseek_manager(prompt, model, timeout)
        except Exception as e:
            return f"DONE manager-brain-error: {type(e).__name__}: {str(e)[:160]}"
    try:
        proc = subprocess.run(["claude", "-p", "--model", model,
                               "--disallowedTools", "Bash", "Edit", "Write", "Read",
                               "NotebookEdit", "Glob", "Grep", "Task",
                               "WebSearch", "WebFetch"],
                              input=MANAGER_SYS + "\n\n" + prompt,
                              capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return f"DONE manager-brain-error: {type(e).__name__}"
    if proc.returncode != 0:
        return f"DONE manager-brain-error: {(proc.stderr or '').strip()[:160] or 'claude -p failed'}"
    return proc.stdout.strip()

_FENCE = re.compile(r"```(?:bash|sh)?\s*\n?(.+?)```", re.S)
_VERB  = re.compile(r"^\s*(TASK|FINDING|VERDICT|HYPOTHESIS|DONE|AUTOTURRET)\b(.*)$", re.M)
_WHY   = re.compile(r"^\s*WHY\s*:\s*(.+)$", re.M | re.I)
# H1: the manager must issue plain-English intent, never a command. Reject a TASK whose body is
# actually shell (fenced code, a leading tool binary + flags, pipes/redirects/operators) so a
# command-shaped response is never dispatched as if it were an objective.
_FENCED   = re.compile(r"```")
_CMDSHAPE = re.compile(
    r"(^|\s)(sudo\s+|nmap|curl|wget|gobuster|ffuf|nikto|hydra|smbclient|smbmap|crackmapexec|"
    r"nxc|impacket-\w+|msfconsole|msfvenom|nc\b|ncat|python[23]?\s+-c|bash\s+-c|ssh\b|"
    r"dig|nslookup|enum4linux|searchsploit|/bin/|/usr/bin/)"
    r"|[|;>]\s|\&\&|\$\(|-oN\b|--script\b|RHOSTS?=|LHOST=", re.I)
def _looks_like_command(task, raw):
    if _FENCED.search(raw or ""):
        return True
    t = (task or "").strip()
    # a genuine objective is prose; a command is short, tokeny, and starts with a tool
    return bool(_CMDSHAPE.search(t)) and len(t.split()) <= 40


def parse_rationale(text):
    """Extract the optional manager WHY: rationale line (audit only; never executed)."""
    m = _WHY.search(text or "")
    return m.group(1).strip()[:400] if m else ""

def parse_action(text):
    """(verb, arg). For TASK, arg is the plain-English objective (prose) the manager hands the
    trooper — strip any leading ':' and cap length; the trooper authors the actual commands."""
    m = _VERB.search(text or "")
    if not m:
        return None, (text or "").strip()[:200]
    verb, tail = m.group(1), m.group(2).strip()
    if verb == "TASK":
        return "TASK", tail.lstrip(":").strip()[:600]
    return verb, tail



# ---- AUTOTURRET RECIPES: the deterministic autocannon (live/recipes.py). No LLM in the loop;
# grounded verify predicates; same fact vocabulary the engine parses. We keep ONE Recipes(target)
# per run so chain state (rce_ok, creds, socks, rooted) persists across steps, and every recipe
# command execs via the §10.1 door exactly like the trooper. CANONICAL (2026-08-25): the catalog
# is an implementation LIBRARY, never a parallel decision engine and never a keyword autopilot —
# the manager invokes it EXPLICITLY with the AUTOTURRET verb; nothing here auto-fires on a TASK. ----
_RECIPES = {}
def _recipe_engine(target):
    if target in _RECIPES:
        return _RECIPES[target] or None
    eng = None
    try:
        import recipes as RC
        eng = RC.Recipes(target)
    except Exception:
        eng = None
    _RECIPES[target] = eng
    return eng

def _autoturret_offers(cart):
    """CHEAP lanes whose precondition the live map satisfies — the manager's AUTOTURRET menu.
    Pure INDEX over the catalog (recipes.available_for): fires nothing, decides nothing."""
    try:
        import recipes as RC
    except Exception:
        return []
    ports = [int((n.get("meta") or {}).get("port"))
             for n in (cart.doc or {}).get("nodes", {}).values()
             if n.get("kind") == "port"
             and str((n.get("meta") or {}).get("port", "")).isdigit()]
    try:
        return RC.available_for(ports)
    except Exception:
        return []


def _vhost_verify_hint(task, target, cart):
    """If the manager's objective names a vhost on the map, suggest a content-comparison command
    FIRST: ffuf vhost hits are often wordlist ghosts serving the default site (run 743 steps 6-7
    chased gitlab/wordpress/drupal vhosts that never served those apps). The suggested command
    prints VHOST_GHOST_SAME_CONTENT / VHOST_REAL_DISTINCT for the trooper to report."""
    if not cart or not (task or "").strip():
        return None
    names = []
    for nid, n in (cart.doc or {}).get("nodes", {}).items():
        if n.get("kind") == "vhost":
            name = (n.get("label") or nid.split(":", 1)[-1] or "").strip()
            if name:
                names.append(name.lower())
    if not names:
        return None
    low = task.lower()
    hit = None
    for name in sorted(set(names), key=len, reverse=True):   # longest name match first
        if name in low:
            hit = name
            break
    if not hit:
        return None
    return ("curl -s -o /tmp/gb_vh_default http://{t}/ -w 'DEFAULT_SIZE=%{{size_download}}\\n'; "
            "curl -s -o /tmp/gb_vh_candidate -H 'Host: {v}' http://{t}/ -w 'VHOST_SIZE=%{{size_download}}\\n'; "
            "cmp -s /tmp/gb_vh_default /tmp/gb_vh_candidate && echo VHOST_GHOST_SAME_CONTENT "
            "|| echo VHOST_REAL_DISTINCT; rm -f /tmp/gb_vh_default /tmp/gb_vh_candidate"
            ).format(t=target, v=hit)


def _ghost_from_output(out):
    """Vhost-verify outcome from the trooper transcript: returns the vhost name if the
    content comparison printed VHOST_GHOST_SAME_CONTENT (a wordlist artifact serving the
    default site), else None. Deterministic ghost-kill: the manager folds dead=<vhost>
    itself rather than trusting the trooper to report the outcome (run 744 step 4)."""
    if "VHOST_GHOST_SAME_CONTENT" not in (out or ""):
        return None
    m = re.search(r"Host:\s*'?([A-Za-z0-9.\-]+)", out or "")
    return m.group(1) if m else None


def _reals_from_output(out):
    """Vhost-verify outcome: the names the comparison proved REAL (VHOST_REAL_DISTINCT).
    Promoted from UNVERIFIED to the real frontier (verified=)."""
    if "VHOST_REAL_DISTINCT" not in (out or ""):
        return []
    names = set()
    for m in re.finditer(r"Host:\s*'?([A-Za-z0-9.\-]+)", out or ""):
        names.add(m.group(1))
    return sorted(names)


def _batch_vhost_verify(target, cart, ts, emit):
    """VERIFY AT INGESTION — owned by HANDS (canonical: hands gathers, cartographer records):
    every UNVERIFIED vhost node gets content-compared against the default site through the
    §10.1 door. Fuzz facts are wordlist ghosts until proven otherwise (runs 743-745: each
    re-fuzz re-added ~19 ghost vhosts to the frontier and the manager chased them for steps).
    GHOST -> dead=<v>; REAL -> verified=<v> (promoted to the frontier). Capped per batch so
    the command stays bounded; leftovers stay UNVERIFIED for the next step.
    Returns (ghosts, reals)."""
    names = []
    for nid, n in (cart.doc or {}).get("nodes", {}).items():
        if n.get("kind") == "vhost" and n.get("state") == UNVERIFIED:
            name = (n.get("label") or nid.split(":", 1)[-1] or "").strip()
            if name:
                names.append(name.lower())
    names = sorted(set(names))
    if not names:
        return 0, 0
    try:
        ghosts, reals = HANDS.verify_vhosts(
            target, names,
            runner=lambda cmd, t: TEXEC.run(cmd, target, action_class="web.recon", timeout=t),
            cap=12)
    except Exception as e:
        emit("vhost_verify", step=ts, error=str(e)[:100], n=len(names))
        return 0, 0
    if ghosts:
        cart.fold([f"dead={g}" for g in ghosts], ts=ts)
    if reals:
        cart.fold([f"verified={r}" for r in reals], ts=ts)
    if ghosts or reals:
        cart.save(ts)
    emit("vhost_verify", step=ts, ghosts=ghosts, reals=reals,
         ghosts_n=len(ghosts), reals_n=len(reals), n=min(len(names), 12))
    return len(ghosts), len(reals)


def _app_named_in_task(task, cart):
    """The app node whose name the manager's objective names (recipe-first linkage: the
    attack hint and attack receipts key off it). Longest name match wins."""
    if not cart or not (task or "").strip():
        return ""
    low = task.lower()
    best = ""
    for nid, n in (cart.doc or {}).get("nodes", {}).items():
        if n.get("kind") != "app":
            continue
        name = ((n.get("meta") or {}).get("app") or "").strip().lower()
        if len(name) >= 3 and name in low and len(name) > len(best):
            best = name
    return best


def _attack_hint(task, target, cart):
    """RECIPE-FIRST attack seeding: when the objective names an app node with UNFINISHED
    attack rituals, suggest the exploit-DB lookup for that exact product+version as the
    trooper's first command. The recurring stall (runs 741-745) is the trooper spending its
    whole budget re-fingerprinting an app and never firing an exploit; starting it from the
    public exploit record for the named product breaks that loop deterministically."""
    if not cart or not (task or "").strip():
        return None
    low = task.lower()
    best = None
    for nid, n in (cart.doc or {}).get("nodes", {}).items():
        if n.get("kind") != "app":
            continue
        name = ((n.get("meta") or {}).get("app") or "").strip().lower()
        if not name or name not in low:
            continue
        if not {"cve-lookup", "default-creds", "known-exploit-chain"} - set(n.get("rituals_done") or []):
            continue   # every attack ritual already done — nothing left to seed
        ver = ((n.get("meta") or {}).get("version") or "").strip()
        key = (len(name), bool(ver))
        if best is None or key > best[0]:
            best = (key, (f"searchsploit {name} {ver}".strip() + " | head -n 25"))
    return best[1] if best else None


# a task claiming 'we already fired X' is only honored when the map records an attack
# receipt (run 744 step 4: Memoria's 'operator already fired a mail-masta LFI probe' was a
# confabulation and the trooper wasted its budget believing the phantom)
_PRIOR_CLAIM = re.compile(
    r"\b(?:already|previously|earlier|before)\b[^,.;]{0,60}\b(?:fired|ran|tried|tested|"
    r"exploited|sprayed|probed|attempted|sent|launched)\b", re.I)
_ATTACK_DONE = {"cve-lookup", "default-creds", "known-exploit-chain"}


def _prior_attack_proven(task, cart):
    if not _PRIOR_CLAIM.search(task or ""):
        return True   # no claim -> nothing to prove
    low = (task or "").lower()
    apps = list((cart.doc or {}).get("nodes", {}).values())
    named = [n for n in apps
             if n.get("kind") == "app"
             and ((n.get("meta") or {}).get("app") or "").strip().lower() in low]
    if named:
        return any(set(n.get("rituals_done") or []) & _ATTACK_DONE for n in named)
    # no named app: accept only if SOME attack was ever recorded on the map
    return any(set(n.get("rituals_done") or []) & _ATTACK_DONE
               for n in apps if n.get("kind") == "app")


def _sanitize_prior_claims(task, cart):
    """If the task claims a prior action the map does not record, hand the trooper the task
    WITH an engine correction instead of silently trusting the confabulation."""
    if _prior_attack_proven(task, cart):
        return task
    return (task.strip() + "\n(ENGINE CORRECTION: the engagement map records NO such prior probe "
            "on this target — treat that claim as ungrounded memory and run the attack yourself now.)")


def _durable_sync(run_dir, target, boot=False, final=False):
    """Mirror the compact run artifacts to DURABLE_DIR so a /tmp wipe does not erase the
    engagement evidence base. Light: small ledgers only, once per step; never fatal."""
    try:
        base = Path(DURABLE_DIR) / Path(run_dir).name
        base.mkdir(parents=True, exist_ok=True)
        for fn in ("telemetry.jsonl", "cartography.json", "manager_reasoning.jsonl",
                   "state.json", "fire_timeline.txt", "report.json", "report.md"):
            src = Path(run_dir) / fn
            if src.exists():
                shutil.copy2(src, base / fn)
        if boot or final:
            with open(Path(DURABLE_DIR) / "runs_index.tsv", "a") as fh:
                fh.write(f"{int(time.time())}\t{target}\t{'boot' if boot else 'done'}\t{run_dir}\n")
    except Exception:
        pass


def fire_command(task, target, suggest=None, app=None):
    """Hand ONE plain-English objective to the trooper; return SCRUBBED {facts, telemetry, cmds}.
    The manager gives INTENT, never a command. The trooper (scope-guarded) authors and runs
    whatever commands the objective needs, holds its own sessions across turns, and reports back
    only distilled telemetry + scrubbed facts. Full agentic turn budget so it can actually pursue
    the objective (recon -> exploit -> loot within one task), catch and drive a shell it lands in
    the persistent session, and stop on its own when the objective is met or definitively walled.
    app: the app node name the objective targets (recipe-first linkage) — the trooper
    deterministically primes the exploit DB for it before its first turn.

    CANONICAL (2026-08-25): no hidden auto-fire. Recipes are a LIBRARY the trooper consults
    and the manager clears via the explicit AUTOTURRET verb; this function fires the LLM
    trooper for TASK objectives only."""
    # The LLM trooper authors + runs the attempt itself, holding its own session.
    # Ceiling: the turn-leak fix in trooper.py makes the budget real, and with the recon
    # ritual populating the map up front, objectives are focused — no budget goes to
    # re-enumeration. 20 turns is ample for one objective; higher values only buy churn.
    TR.MAX_TURNS = min(int(os.environ.get("GB_TROOPER_TURNS", "12")), 20)
    obj = (task.strip() + "\n\nWork this objective end to end: author and run whatever commands it "
           "takes, adapt to what you see, and use the persistent session for any shell you land. "
           "Report back what you learned in telemetry (services/versions/paths, the wall you hit, "
           "your suggested next move) and facts (flags, creds as '<captured>', shells).")
    lane = {"target": target, "objective": obj}
    if suggest:
        lane["cmd"] = suggest
    if app:
        lane["_app"] = app
    r = TR.Trooper().fire(lane)
    return {"facts": r.get("facts") or [], "telemetry": r.get("telemetry") or {},
            "cmds": r.get("cmds") or [], "success": bool(r.get("success")), "via": "trooper"}


def ariadne_routes(facts, target, cart=None):
    """Best-effort Ariadne feed: backward-chained goal ladder from the facts observed so far.
    Returns (goals, recon_next); fails soft if the feed is unavailable or malformed.
    Rejected hypotheses ride along as typed negatives (critique #8) so Ariadne prunes
    branches the engagement already tested and rejected."""
    if RA is None:
        return [], []
    try:
        negatives = []
        if cart is not None and cart.doc.get("nodes"):
            apps, proven, extra_facts = cart.ariadne_triple()
            negatives = cart.confirmed_negatives()
        elif H is not None:
            apps, proven, extra_facts = H.obs_to_graph(facts)
        else:
            return [], []
        adv = RA.advise_from_state(proven, apps, negatives=negatives, host=target,
                                   extra_facts=extra_facts)
        if not isinstance(adv, dict):
            return [], []
        return adv.get("goals") or [], adv.get("recon_next") or []
    except Exception:
        return [], []


def memoria_hint(observed_tokens):
    """Corpus recall keyed off what's been observed (service/app names). Fails soft to ''."""
    if MEM is None or not observed_tokens:
        return ""
    seed = " ".join(sorted(observed_tokens))[:200]
    try:
        return MEM.hints_for(seed, [], "", k=3, timeout=7) or ""
    except Exception:
        return ""


_TOKEN = re.compile(r"\b(gitlab|wordpress|drupal|joomla|apache|nginx|tomcat|jenkins|ssh|ftp|smb|"
                    r"mysql|postgres|mssql|redis|mongodb|iis|php|python|node|ruby|http|https|rdp|"
                    r"ldap|kerberos|snmp|dns|smtp|nfs|elasticsearch|jira|confluence)\b", re.I)

def observed_tokens(facts, telem_history):
    toks = set()
    blob = " ".join(facts) + " " + " ".join(telem_history)
    for m in _TOKEN.finditer(blob):
        toks.add(m.group(1).lower())
    return toks


import shutil, glob
# curated offensive-tool probe list — GENERAL (not tied to any box); we report which are PRESENT
# on the host the trooper fires from, so the manager reaches for tools that actually exist instead
# of guessing and eating a 'command not found'. This is feeding the picture, not choosing an attack.
_TOOL_PROBE = ["nmap", "masscan", "rustscan", "gobuster", "feroxbuster", "ffuf", "dirb", "dirbuster",
    "nikto", "whatweb", "wpscan", "sqlmap", "hydra", "medusa", "netexec", "crackmapexec", "nxc",
    "smbclient", "smbmap", "enum4linux", "enum4linux-ng", "rpcclient", "ldapsearch", "snmpwalk",
    "onesixtyone", "evil-winrm", "searchsploit", "msfconsole", "curl", "wget", "nc", "ncat", "socat",
    "john", "hashcat", "hashid", "gowitness", "dnsrecon", "dig", "showmount", "redis-cli", "mysql",
    "psql", "mongo", "ssh", "sshpass", "kinit", "python3", "php", "ruby", "perl", "git"]
_TOOL_CACHE = None
def tool_inventory():
    """Report the offensive tools present on the host the TROOPER actually fires from — which is
    the TROOPER_EXEC_SSH host when set (commands run there over ssh), else this host. Host-accurate
    so the manager reaches for tools that really exist on the exec host."""
    global _TOOL_CACHE
    if _TOOL_CACHE is not None:
        return _TOOL_CACHE
    exec_ssh = os.environ.get("TROOPER_EXEC_SSH", "").strip()
    if exec_ssh:
        probe = "; ".join(f'command -v {t} >/dev/null 2>&1 && echo {t}' for t in _TOOL_PROBE) \
                + '; { command -v impacket-secretsdump >/dev/null 2>&1 || command -v secretsdump.py >/dev/null 2>&1; } && echo "impacket-*"'
        try:
            out = subprocess.run(["ssh", "-o", "ControlPath=none", "-o", "ConnectTimeout=10", exec_ssh, probe],
                                 capture_output=True, text=True, timeout=45).stdout
            valid = set(_TOOL_PROBE) | {"impacket-*"}
            present = [l.strip() for l in out.splitlines() if l.strip() in valid]
        except Exception:
            present = []
        bundled = []   # bundled binaries are host-local; don't assume the remote has them
    else:
        present = [t for t in _TOOL_PROBE if shutil.which(t)]
        if shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py"):
            present.append("impacket-*")
        bundled = [os.path.basename(p) for p in glob.glob("/opt/bs2/bin/*") if os.access(p, os.X_OK)]
    _TOOL_CACHE = (present, bundled)
    return _TOOL_CACHE



# ---- proof-guard: the trooper's commands run on the EXEC host (e.g. your-host), so a local `id`/
# `whoami` there yields uid=1000(<opuser>) which the fact-salvage would scrape as a target
# `shell=`/`rce_as=` foothold. Query the exec host's OWN identity once and reject any foothold
# fact that merely reflects it. General: nothing box- or user-specific is hardcoded. ----
_EXEC_IDENT = None
def _exec_host_identities():
    global _EXEC_IDENT
    if _EXEC_IDENT is not None:
        return _EXEC_IDENT
    users = set()
    exec_ssh = os.environ.get("TROOPER_EXEC_SSH", "").strip()
    argv = (["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", exec_ssh, "bash -lc 'id -un; id -u; hostname'"]
            if exec_ssh else ["bash", "-lc", "id -un; id -u; hostname"])
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=15).stdout
        for tok in out.split():
            if tok.strip():
                users.add(tok.strip())
    except Exception:
        pass
    _EXEC_IDENT = users
    return users

def _is_exec_phantom(fact):
    f = str(fact)
    if f.startswith(("shell=", "rce_as=")):
        val = f.split("=", 1)[1].strip().split()[0] if "=" in f else ""
        return val in _exec_host_identities()
    return False

def _drop_phantoms(facts):
    return [f for f in (facts or []) if not _is_exec_phantom(f)]


def _evidence_refs_valid(refs, valid_seqs):
    """Critique #10: a hypothesis may be CONFIRMED only on evidence that exists in THIS
    run's telemetry. Empty, unknown (non-telemetry), or stale (seq not emitted here)
    references are refused — a manager assertion is not proof."""
    refs = list(refs or [])
    if not refs:
        return False
    for r in refs:
        m = re.fullmatch(r"telemetry:(\d+)", str(r).strip())
        if not m or int(m.group(1)) not in valid_seqs:
            return False
    return True


def build_prompt(target, facts, transcript, routes, recon_next, mem, frontier=None,
                 open_hypotheses=None, coverage=None, environment=None,
                 charter_doc=None, autoturret=None, governed=None):
    present, bundled = tool_inventory()
    charter_txt = charter.render(charter_doc) if charter_doc else (
        "# BATTLE CHARTER: (default standing HTB engagement — see charter.py)")
    gov_txt = ""
    if governed:
        caps = ", ".join(governed.get("caps") or ["none"])
        if governed.get("witnessed"):
            ceiling = "witnessed seam: exploit allowed up to high-risk; destructive always denied"
        else:
            ceiling = ("RECON-ONLY: only impact=read commands pass (nmap / curl-GET family); "
                       "mutation and exploit-class commands are DENIED")
        gov_txt = f"""
# GOVERNED EXECUTION (fail-closed — respect these ceilings)
- capability classes: {caps}
- ceiling: {ceiling}
- RULE: never re-author a command family the previous marker shows denied — fold the
  denial, adapt, or terminate honestly. Denied attempts burn the step budget.
"""
    at_txt = ("\n".join(f"- {l}" for l in (autoturret or []))
              or "(no cheap lanes match the current map)")
    at_block = f"""
# AUTOTURRET OFFERS (deterministic low-hanging-fruit lanes matching your map)
{at_txt}
AUTOTURRET is YOUR tool: say AUTOTURRET and I clear all offered lanes now — ground-level
trades you should not spend trooper turns on. It fires ONLY when you invoke it, never by itself."""
    tools_txt = ", ".join(present) or "(none detected — fall back to curl/wget/bash builtins)"
    bundled_txt = (f"\nBundled at /opt/bs2/bin (invoke by full path): "
                   + ", ".join(f"/opt/bs2/bin/{b}" for b in bundled)) if bundled else ""
    steps = "\n".join(f"{i+1}. {a}\n     -> {m}" for i, (a, m) in enumerate(transcript)) \
            or "(nothing yet — issue your first recon objective)"
    fmap = "\n".join(f"- {f}" for f in facts) or "(no confirmed facts yet)"
    rtxt = "\n".join(
        f"- goal {g.get('goal')}: status={g.get('status')} path: "
        + (" -> ".join(str(x) for x in (g.get('path') or [])) or "(direct)")
        for g in (routes or [])[:8]) or "(planner offline or no routes yet)"
    recon_txt = "\n".join(
        f"- confirm {row.get('confirm')} (unblocks {row.get('unblocks_goal')}, "
        f"gain {row.get('gain')})"
        for row in (recon_next or [])[:5]
    ) or "(no forward frontier — graph ungrounded or goals already met)"
    frontier_rows = (frontier or [])[:8]
    frontier_txt = "\n".join(
        f"- {row.get('label')} [{row.get('state')}]  -> not yet: "
        f"{', '.join(str(x) for x in (row.get('suggest') or [])) or '(none)'}"
        f"   (notes: {'; '.join(str(x) for x in (row.get('notes') or [])) or 'none'})"
        for row in frontier_rows
    ) or "(no discovery edges recorded yet)"
    frontier_classes = [
        ritual
        for row in frontier_rows
        for ritual in (row.get("suggest") or [])
    ]
    enumerate_txt = "\n".join(
        f"- {ritual}: {guide}"
        for ritual, guide in CG.guide_for(frontier_classes)[:10]
    ) or "(no class-specific guidance for the current frontier)"
    hypotheses_txt = "\n".join(
        f"- [{row.get('id')}] {row.get('vuln_class')} @ {row.get('node')}  "
        f"conf={row.get('confidence')} status={row.get('status')}  "
        f"validate: {row.get('required_validation')}"
        for row in (open_hypotheses or [])[:8]
    ) or "(none yet — raise by enumerating the surface)"
    coverage = coverage or {
        "surface": {"pct": 100.0, "untouched": []},
        "hypotheses": {"open_count": 0},
        "findings_count": 0,
        "complete": True,
        "blockers": [],
    }
    coverage_pct = f"{coverage['surface']['pct']:.1f}".rstrip("0").rstrip(".")
    if coverage["complete"]:
        coverage_status = ("COMPLETE — objective achieved (foothold)"
                           if coverage.get("objective_achieved")
                           else "COMPLETE — exhausted WITHOUT compromise")
    else:
        coverage_status = "INCOMPLETE"
    coverage_txt = (
        f"{coverage_pct}% surface enumerated | "
        f"{len(coverage['surface']['untouched'])} untouched | "
        f"{coverage['hypotheses']['open_count']} open hypotheses | "
        f"{coverage['findings_count']} findings | {coverage_status}"
    )
    if not coverage["complete"]:
        coverage_txt += "\n" + "\n".join(
            f"- still to do: {blocker}" for blocker in coverage["blockers"][:4]
        )
    # ENVIRONMENT (lateral surface) — only when the engagement has spread past one clean host
    env = environment or {}
    env_hosts = env.get("hosts") or []
    env_sessions = env.get("sessions") or []
    env_creds = env.get("credentials") or []
    env_has_foothold = any(h.get("state") == "led-to-foothold" for h in env_hosts)
    show_env = len(env_hosts) > 1 or bool(env_sessions) or env_has_foothold
    env_block = ""
    if show_env:
        fbh = env.get("frontier_by_host") or {}
        host_lines = "\n".join(
            f"- {h.get('ip')} [{h.get('state')}]"
            + (f"  via {h.get('opened_by')}" if h.get("opened_by") not in ("map.json", "", None) else "")
            + (f"   open: {', '.join((fbh.get(h.get('ip')) or [])[:6])}" if fbh.get(h.get("ip")) else "")
            for h in env_hosts
        ) or "- (none)"
        sess_lines = "\n".join(
            f"- {s.get('id')}  {s.get('user') or '?'}@{s.get('via_host') or '?'}/{s.get('protocol') or '?'}"
            for s in env_sessions
        ) or "- (no live sessions recorded)"
        cred_lines = "\n".join(
            f"- {c.get('user')}  works_on={c.get('works_on') or '-'}  failed_on={c.get('failed_on') or '-'}"
            for c in env_creds
        ) or "- (no credential applicability recorded)"
        env_block = f"""

# ENVIRONMENT (hosts / sessions / credentials — lateral surface)
Hosts:
{host_lines}
Sessions:
{sess_lines}
Credentials:
{cred_lines}
After a foothold, enumerate the interior frontier (identity / local / privesc / netview) and expand laterally — discovered internal hosts become NEW roots with their own frontier; track where each credential works vs. is rejected before spraying (mind lockouts)."""
    return f"""{charter_txt}{gov_txt}

# ENGAGEMENT
Authorized HTB target: {target}   (reach it over the operator's HTB VPN)
Goal: OWN THE NETWORK. Foothold shell -> loot & crack creds -> pivot to the internal DC -> Domain
Admin. Build the map first, then exploit what you find. A stray flag file is a NOTE, not the goal —
keep going. (Full staged objective is in your system brief.)

# COVERAGE (are we actually done?)
{coverage_txt}

# MAP so far (confirmed scrubbed facts)
{fmap}

# CARTOGRAPHER — DISCOVERY FRONTIER (what you have NOT enumerated yet)
{frontier_txt}
The frontier is the authoritative record of untouched surface; prefer closing open enumeration edges (especially vhosts on HTTP ports) before deep single-path exploitation, but you remain the shot-caller and may override it with a reason.
Enumeration is full-spectrum (passive DNS, subdomains, JS/secret extraction, API/GraphQL, source/cloud exposure, authenticated crawl), not just dirs/vhosts; mark a class done/NA via the normal flow when it is not applicable to this target.

# HOW TO ENUMERATE (guidance for the classes on your frontier)
{enumerate_txt}

# OPEN HYPOTHESES (validate → then VERDICT confirmed/rejected/inconclusive)
{hypotheses_txt}{env_block}

# TOOLS AVAILABLE TO YOUR TROOPER (capability context only — you name the INTENT, the trooper picks the tool)
{tools_txt}{bundled_txt}

# PROPOSED ROUTES (Ariadne — advisory)
{rtxt}

# ARIADNE — CONFIRM NEXT (forward frontier)
{recon_txt}
{("# MEMORIA (hints from PRIOR engagements — what worked on similar surfaces before; nothing "
  "here proves anything about THIS target, verify before acting)\n" + mem) if mem
 else "# MEMORIA: (no corpus hints yet — will key off observed services)"}

# YOUR TASKS & THE SANITIZED MARKERS THAT CAME BACK
{steps}
{at_block}
# YOUR MOVE
Issue exactly ONE next action (one line: TASK <plain-English objective> / AUTOTURRET / VERDICT ... / HYPOTHESIS ... / FINDING <text> / DONE <reason>). Plain DONE is accepted only when coverage is COMPLETE; to stop early use DONE FORCE <reason>. Nothing else."""


def _run_identity(target, charter_doc, ts):
    """Deterministic run-dir/hold-session identity. Two concurrent runs against the
    SAME host (local lab apps share 127.0.0.1) must never share state: when the charter
    declares scope.ports, the port set names the run (lab pass 1 collision: both runs
    landed in htb-127-0-0-1-<ts> and one tmux hold session)."""
    ports = sorted({str(p) for p in ((charter_doc or {}).get("scope") or {}).get("ports") or []})
    tag = f"-p{'-'.join(ports)}" if ports else ""
    return f"{target.replace('.', '-')}{tag}-{ts}"


def _governed_info(seam_dir):
    """The governed picture the manager reasons under: capability classes + witnessed
    status, read from the seam the door is bound to. None = ungoverned."""
    seam_dir = (seam_dir or "").strip()
    if not seam_dir:
        return None
    try:
        seam = json.loads(open(f"{seam_dir}/seam.json").read())
    except Exception:
        return None
    caps = sorted(seam.get("caps") or [])
    return {"caps": caps, "witnessed": "web.exploit" in caps}


def _hold_session(action, name):
    """Create or kill the persistent tmux 'hold' session the trooper lands shells in.
    Runs on the exec host (TROOPER_EXEC_SSH, e.g. your-host) when set, else locally. Best-effort:
    a tmux/ssh hiccup never blocks the engagement (the trooper still runs one-shot RCE)."""
    import shlex
    exec_ssh = os.environ.get("TROOPER_EXEC_SSH", "").strip()
    if action == "up":
        inner = f"tmux has-session -t {shlex.quote(name)} 2>/dev/null || tmux new-session -d -s {shlex.quote(name)}"
    else:
        inner = f"tmux kill-session -t {shlex.quote(name)} 2>/dev/null || true"
    argv = (["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", exec_ssh, "bash -lc " + shlex.quote(inner)]
            if exec_ssh else ["bash", "-lc", inner])
    try:
        subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--steps", type=int, default=30)
    ap.add_argument("--model", default="deepseek-v4-pro")
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--seed-facts", default=None,
                    help="path to a prior state.json; its facts are preloaded and folded so the "
                         "manager resumes at the discovered stage instead of redoing recon")
    a = ap.parse_args()
    target = a.target
    # --- BATTLE CHARTER (canonical loop top): load, bind, and GATE the run on it ---
    charter_doc, charter_src = charter.load()
    charter.bind_target(charter_doc, target)
    ok_charter, why_charter = charter.validate_target(charter_doc, target)
    if not ok_charter:
        print(f"[charter] REFUSING to start: {why_charter}")
        sys.exit(1)
    # loopback policy follows the CHARTERED TARGET, not the process env: a local-lab
    # engagement (juice/crAPI on 127.0.0.1) re-enables the trooper's loopback carve-out
    # after the import-time pop; an HTB target keeps the hard loopback deny. The trooper
    # reads the flag at fire time (lab passes 2-3 silently walled on this).
    if target in ("127.0.0.1", "localhost", "::1") or str(target).startswith("127."):
        os.environ["GB_ALLOW_LOOPBACK"] = "1"
        # charter PORT scoping rides to the trooper (pass-4 lesson 2026-08-25): the
        # loopback carve-out opens the host; the declared ports keep the trooper path
        # inside the charter the way hands' charter-scoped sweeps already do.
        _cports = (charter_doc.get("scope") or {}).get("ports") or []
        if _cports:
            os.environ["GB_CHARTER_PORTS"] = ",".join(str(p) for p in _cports)
    else:
        os.environ.pop("GB_ALLOW_LOOPBACK", None)
        os.environ.pop("GB_CHARTER_PORTS", None)
    # --- governed mode (canonical BS2-evaluate): GB_GOVERNED=1 requires an open seam; fail-closed ---
    # The seam is open locally (BS2_SEAM_RUN) or dispatched via ssh to the exec host
    # (GB_GOVERNED_HOST + GB_GOVERNED_SEAM_DIR / BS2_SEAM_RUN-as-remote-path).
    gov_seam = os.environ.get("BS2_SEAM_RUN", "").strip()
    gov_remote = (os.environ.get("GB_GOVERNED_HOST", "").strip()
                  and (os.environ.get("GB_GOVERNED_SEAM_DIR", "").strip() or gov_seam))
    gov_mode = "governed" if (gov_seam or gov_remote) else "ungoverned"
    gov_info = _governed_info(gov_seam) if gov_mode == "governed" else None
    if os.environ.get("GB_GOVERNED", "0") == "1" and gov_mode == "ungoverned":
        print("[governed] GB_GOVERNED=1 but no seam is open (BS2_SEAM_RUN or "
              "GB_GOVERNED_HOST+GB_GOVERNED_SEAM_DIR) — refusing to start "
              "(fail-closed: governed runs need an open seam).")
        sys.exit(1)
    run_ts = int(time.time())
    run_dir = a.run_dir or f"/tmp/claude-1000/-home-om/htb-{_run_identity(target, charter_doc, run_ts)}"
    os.makedirs(run_dir, exist_ok=True)
    # Lenz is a translation layer, not the harness event format. It exists for the Codex
    # consumers; the manager loop runs with it OFF by default (GB_LENZ=1 re-enables it).
    lenz = (SafeLenzStream.mirror(steps=a.steps) if os.environ.get("GB_LENZ", "0") == "1"
            else NullLenz())
    # persistent tmux 'hold' session: the trooper lands interactive/reverse shells here so a
    # foothold survives across manager consultations (see trooper SYS PERSISTENT SESSION).
    sess_name = f"gb-{_run_identity(target, charter_doc, run_ts)}"
    os.environ["GB_SESSION"] = sess_name
    _hold_session("up", sess_name)

    facts, transcript, telem_history = [], [], []
    end_kind = None   # how the loop ended: done | done_forced | stop | (steps exhausted)
    last_run_evidence_refs = []
    denial_streak = 0
    seen_facts = set()
    C = CG.Cartographer(run_dir)
    # ONE no-repeat experiment ledger per run (2026-08-25): every experiment lane
    # (slice, matrix, lab) opens the SAME instance, so overlapping experiments dedup
    # across specialists and across runs.
    C.experiment_ledger = ExperimentLedger.open(run_dir)
    ports_seeded = any(n.get("kind") == "port" for n in C.doc.get("nodes", {}).values())
    last_surf = None   # last surface map written to map.json — re-ingest only on change
    # --- TELEMETRY: an append-only, timestamped, ordered record of every event, so the exact
    #     firing sequence + timing is durably captured for SOP assessment. One JSON row per event. ---
    tpath = f"{run_dir}/telemetry.jsonl"
    _t0 = time.time()
    _seq = [0]
    _valid_seqs = set()   # every seq this run emitted — the evidence-ref validity set
    def emit(kind, **kw):
        _seq[0] += 1
        _valid_seqs.add(_seq[0])
        now = time.time()
        row = {"seq": _seq[0], "event": kind, "ts_epoch": round(now, 3),
               "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
               "elapsed_s": round(now - _t0, 1), **kw}
        print(f"[{kind}] " + " ".join(f"{k}={v}" for k, v in kw.items())[:400], flush=True)
        try:
            with open(tpath, "a") as fh:
                fh.write(json.dumps(row) + "\n")
        except Exception:
            pass
        lenz.observe(kind, **kw)
        if kind == "manager":
            _verb = str(kw.get("verb", "INVALID")).lower()
            lenz.translate(int(kw.get("step", 0)), "manager", "manager_action",
                           int(kw.get("routes", 0)), 0,
                           _verb if _verb in {"run", "finding", "hypothesis", "verdict", "done",
                                              "autoturret", "invalid"} else "invalid")
        elif kind == "ran":
            lenz.translate(int(kw.get("step", 0)), "hands", "hands_result",
                           int(kw.get("cmds", 0)), 0,
                           "blocked" if kw.get("blocked") else "completed")
        elif kind == "coverage":
            lenz.translate(int(kw.get("step", 0)), "feed", "coverage_update",
                           int(round(float(kw.get("pct", 0)))), int(kw.get("untouched_count", 0)),
                           "complete" if kw.get("complete") else "ongoing")
        elif kind in {"stop", "done", "done_forced", "done_refused", "report"}:
            _statuses = {"stop": "stopped", "done": "complete", "done_forced": "forced",
                         "done_refused": "refused",
                         "report": "complete" if kw.get("complete") else "stopped"}
            lenz.translate(int(kw.get("step", 0) or 0), "system", "run_finished",
                           status=_statuses[kind])
        return row
    emit("boot", target=target, steps=a.steps, brain=a.model, hands=os.environ["TROOPER_MODEL"],
         exec_host=os.environ.get("TROOPER_EXEC_SSH", "local"), run_dir=run_dir,
         hold_session=sess_name, mode=gov_mode, charter=charter_src)
    _durable_sync(run_dir, target, boot=True)

    # --- resume: preload the discovered picture so the manager starts at the foothold stage ---
    if a.seed_facts and os.path.exists(a.seed_facts):
        try:
            seed = json.load(open(a.seed_facts)).get("facts", [])
        except Exception:
            seed = []
        seed = _drop_phantoms(seed)
        for f in seed:
            if f not in seen_facts:
                seen_facts.add(f); facts.append(str(f))
        pm = _surface_to_mapjson(facts, {}, target)
        if pm is not None:
            with open(f"{run_dir}/map.json", "w") as fh:
                json.dump(pm, fh, indent=2)
            C.ingest_map_json(0); C.save(0); ports_seeded = True; last_surf = pm
        C.fold(facts, ts=0); C.save(0)
        emit("seeded", n=len(facts), source=os.path.basename(a.seed_facts),
             folded_facts=list(facts))

    # --- deterministic recon ritual: populate the map BEFORE the manager's first turn ---
    #     Off with GB_RECON_RITUAL=0 (rollback hatch). Skipped automatically on --seed-facts
    #     resume, where the map is already populated.
    if os.environ.get("GB_RECON_RITUAL", "1") == "1" and not ports_seeded:
        surf = _recon_ritual(target, emit,
                             ports=(charter_doc.get("scope") or {}).get("ports"))
        if surf is not None:
            with open(f"{run_dir}/map.json", "w") as fh:
                json.dump(surf, fh, indent=2)
            C.ingest_map_json(0); C.save(0)
            ports_seeded = True; last_surf = surf
            if a.seed_facts:
                # the seed fold above ran BEFORE the ports existed, so enum receipts no-op'd;
                # re-fold now that the map is ingested (idempotent) so resume keeps receipts
                C.fold(facts, ts=0); C.save(0)

    for step in range(1, a.steps + 1):
        toks = observed_tokens(facts, telem_history)
        routes, recon_next = ariadne_routes(facts, target, cart=C)
        mem = memoria_hint(toks)
        frontier = C.frontier(top=8)
        open_hyps = C.open_hypotheses(8)
        coverage = C.coverage_report()
        env_map = C.environment_map()
        emit("coverage", step=step, pct=coverage["surface"]["pct"],
             open_count=coverage["hypotheses"]["open_count"],
             untouched_count=len(coverage["surface"]["untouched"]),
             unattacked_count=len(coverage.get("unattacked_apps") or []),
             complete=coverage["complete"])
        _durable_sync(run_dir, target)   # mirror prior-step artifacts out of /tmp every step
        _env_foothold = any(h.get("state") == "led-to-foothold" for h in env_map["hosts"])
        if len(env_map["hosts"]) > 1 or env_map["sessions"] or _env_foothold:
            emit("environment", step=step, host_count=len(env_map["hosts"]),
                 session_count=len(env_map["sessions"]), cred_count=len(env_map["credentials"]))
        prompt = build_prompt(target, facts, transcript, routes, recon_next, mem,
                              frontier=frontier, open_hypotheses=open_hyps,
                              coverage=coverage, environment=env_map,
                              charter_doc=charter_doc,
                              autoturret=_autoturret_offers(C),
                              governed=gov_info)
        raw = call_manager(prompt, model=a.model)
        # empty completion (model burned its whole budget thinking, run 741 steps 4+6): retry
        # once before burning the step on an INVALID verb
        if not (raw or "").strip():
            time.sleep(5)
            raw = call_manager(prompt, model=a.model)
        verb, arg = parse_action(raw)
        why = parse_rationale(raw)
        emit("manager", step=step, verb=verb or "INVALID", routes=len(routes), memoria=bool(mem),
             why=(why or "(none given)"), action=(arg if arg else raw[:400]))
        # durable per-decision audit: the manager's reasoning (why), the authored action, and the
        # verbatim reply — so the ORDER + WHEN + WHY of every decision is reconstructable offline.
        try:
            with open(f"{run_dir}/manager_reasoning.jsonl", "a") as fh:
                fh.write(json.dumps({
                    "seq": _seq[0], "step": step,
                    "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                    "elapsed_s": round(time.time() - _t0, 1),
                    "verb": verb or "INVALID", "action": arg, "why": why,
                    "coverage_pct": coverage["surface"]["pct"],
                    "open_hypotheses": [h.get("id") for h in open_hyps],
                    "raw": raw[:2000],
                }) + "\n")
        except Exception:
            pass

        if verb is None:
            # one corrective re-prompt instead of burning the step on a reply with no action
            # line (same pattern as the empty-completion retry)
            raw2 = call_manager(prompt + "\n\nREJECTED: your reply had no action line. "
                                "Re-issue EXACTLY ONE action line (TASK ... / VERDICT ... / "
                                "HYPOTHESIS ... / FINDING ... / DONE ...).", model=a.model)
            verb2, arg2 = parse_action(raw2)
            if verb2 is not None:
                emit("manager_retry", step=step, reason="no valid action line", recovered=True)
                verb, arg = verb2, arg2
            else:
                transcript.append(("(no valid action line)", "reply with ONE action line only"))
                if step > 1 and transcript[-2][0] == "(no valid action line)":
                    emit("stop", reason="manager emitted no valid action twice")
                    end_kind = "stop"; break
                continue
        if verb == "TASK" and _looks_like_command(arg, raw):
            # one corrective re-prompt instead of burning the step (run 745 step 1 rejected
            # a command-shaped TASK and the whole step was lost)
            raw2 = call_manager(prompt + "\n\nREJECTED: your TASK was a command, not a plain-English "
                                "objective. Re-issue ONE action line: TASK <what to achieve>. The "
                                "trooper authors every command.", model=a.model)
            verb2, arg2 = parse_action(raw2)
            if verb2 == "TASK" and not _looks_like_command(arg2, raw2):
                emit("manager_retry", step=step, reason="command-shaped TASK", recovered=True)
                verb, arg = verb2, arg2
            else:
                emit("rejected", step=step, reason="manager emitted a command, not a plain objective")
                transcript.append(("(rejected: command-shaped, not an objective)",
                                   "Re-issue as TASK <plain-English objective> — describe WHAT to achieve, "
                                   "not the command. The trooper authors commands."))
                continue

        if verb == "DONE":
            forced = re.match(r"^(?:FORCE\b|--force\b)\s*(.*)$", arg or "", re.I)
            if forced:
                reason = forced.group(1).strip() or "no reason provided"
                emit("done_forced", reason=reason[:200])
                end_kind = "done_forced"; break
            if coverage["complete"]:
                emit("done", reason=arg[:200], outcome=coverage.get("outcome"),
                     objective_achieved=coverage.get("objective_achieved", False))
                end_kind = "done"; break
            blockers = "; ".join(coverage["blockers"])
            rejection = (f"DONE refused — engagement not complete: {blockers}; "
                         "keep working or justify with DONE FORCE")
            transcript.append((f"DONE {arg[:160]}", rejection))
            emit("done_refused", step=step, blockers=coverage["blockers"])
            continue
        if verb == "FINDING":
            if arg and arg not in seen_facts:
                seen_facts.add(arg); facts.append(f"finding={arg}")
            transcript.append((f"FINDING {arg[:160]}", "recorded"))
            emit("finding", text=arg[:200]); continue

        if verb == "HYPOTHESIS":
            parsed = re.fullmatch(r"(\S+)\s+@\s+(.+?):\s+(.+)", arg or "")
            if not parsed:
                transcript.append((f"HYPOTHESIS {arg[:160]}",
                                   "invalid syntax; use HYPOTHESIS <class> @ <node>: <title>"))
                continue
            vuln_class, locus, title = (part.strip() for part in parsed.groups())
            node_id = locus
            if node_id not in C.doc.get("nodes", {}):
                node_id = next((nid for nid, node in sorted(C.doc.get("nodes", {}).items())
                                if (node.get("meta") or {}).get("handle") == locus), locus)
            hid = HYP.raise_hypothesis(
                C.doc, node=node_id, vuln_class=vuln_class, locus=locus, title=title,
                raised_from=["manager"], confidence="low",
                required_validation=HYP.required_validation_for_class(vuln_class),
                impact=f"Potential {vuln_class} impact if validated.", severity="medium", ts=step)
            C.save(step)
            transcript.append((f"HYPOTHESIS {arg[:160]}", f"recorded as {hid}"))
            hyp = C.doc["hypotheses"][hid]
            emit("hypothesis_raised", step=step, hypothesis_id=hid,
                 vuln_class=hyp.get("vuln_class"), node=hyp.get("node"),
                 locus=hyp.get("locus"), title=hyp.get("title"),
                 confidence=hyp.get("confidence"),
                 required_validation=hyp.get("required_validation"),
                 severity=hyp.get("severity"), impact=hyp.get("impact"),
                 raised_from=["manager"], source="manager")
            continue

        if verb == "VERDICT":
            parsed = re.fullmatch(
                r"(\S+)\s+(confirmed|rejected|inconclusive):\s*(.+)", arg or "")
            if not parsed:
                transcript.append((f"VERDICT {arg[:160]}",
                                   "invalid syntax; use VERDICT <id> <verdict>: <reason>"))
                continue
            hid, verdict, reason = parsed.groups()
            hyp = C.doc.get("hypotheses", {}).get(hid)
            if hyp is None:
                transcript.append((f"VERDICT {arg[:160]}", "unknown hypothesis id; no change"))
                continue
            if hyp.get("status") not in {"proposed", "testing"}:
                transcript.append((f"VERDICT {arg[:160]}",
                                   f"already terminal: {hyp.get('status')}; no change"))
                continue
            if verdict == "confirmed" and not _evidence_refs_valid(last_run_evidence_refs, _valid_seqs):
                # evidence gate (critique #10): confirmation requires a telemetry reference
                # from THIS run — the previous action must have been a TASK that produced it
                transcript.append((f"VERDICT {arg[:160]}",
                                   "REFUSED: confirmation requires evidence from this run's "
                                   "telemetry (run a TASK proving it first)"))
                emit("verdict_refused", step=step, hypothesis_id=hid,
                     reason="no valid evidence refs")
                continue
            if hyp.get("status") == "proposed":
                C.set_testing(hid, step, "manager recorded a verdict")
            before_findings = {f.get("id") for f in C.findings()}
            finding_id = C.resolve_hypothesis(
                hid, verdict, evidence_refs=list(last_run_evidence_refs), reason=reason, ts=step)
            C.save(step)
            transcript.append((f"VERDICT {arg[:160]}",
                               f"recorded {verdict}; evidence={','.join(last_run_evidence_refs) or 'none'}"))
            emit("verdict", step=step, hypothesis_id=hid, verdict=verdict,
                 evidence_refs=list(last_run_evidence_refs), reason=reason[:200])
            if finding_id and finding_id not in before_findings:
                emit("finding", step=step, finding_id=finding_id,
                     from_hypothesis=hid, evidence_refs=list(last_run_evidence_refs))
            continue

        if verb == "AUTOTURRET":
            # MANAGER-OWNED automated clearing of low-hanging fruit (canonical): fires ONLY
            # when the manager invokes it — never a hidden keyword auto-fire. Cheap proven
            # lanes whose precondition the map satisfies, through the §10.1 door; receipts
            # fold like any other run.
            t0 = time.time()
            lanes_now = _autoturret_offers(C)
            eng = _recipe_engine(target)
            used, grounded, at_facts, at_cmds = [], False, [], []
            if lanes_now and eng is not None:
                for lane in lanes_now:
                    try:
                        v = eng.fire({"id": lane})
                    except Exception:
                        v = None
                    if not v:
                        continue
                    used.append(lane)
                    at_cmds += (v.get("cmds") or [])
                    for f in (v.get("facts") or []):
                        if f not in at_facts:
                            at_facts.append(f)
                    if any(str(f).startswith(("shell=", "rce_as=", "flag=", "cred=", "hash=", "root="))
                           for f in (v.get("facts") or [])):
                        grounded = True
            at_facts = _drop_phantoms(at_facts)
            if at_facts:
                C.fold(at_facts, ts=step)
                C.save(step)
            marker = (f"autoturret cleared: {', '.join(used) or '(no lanes matched)'} | "
                      f"facts: {', '.join(str(f) for f in at_facts)[:200] or 'none'}")
            transcript.append(("AUTOTURRET", marker))
            for f in at_facts:
                if f not in seen_facts:
                    seen_facts.add(f)
                    facts.append(str(f))
            emit("autoturret", step=step, lanes=",".join(used), grounded=grounded,
                 cmds=len(at_cmds), facts_n=len(at_facts),
                 folded_facts=at_facts, secs=int(time.time() - t0))
            continue

        # verb == TASK: hand the plain objective to the trooper, scrub, feed back
        task = arg
        _app = _app_named_in_task(task, C)
        task = _sanitize_prior_claims(task, C)
        t0 = time.time()
        # recipe-first: seed the exploit-DB lookup for a named app with unfinished attack
        # rituals (attack-stall breaker); else the vhost content-compare when the
        # objective names a vhost
        res = fire_command(task, target, suggest=(_attack_hint(task, target, C)
                                                  or _vhost_verify_hint(task, target, C)),
                           app=_app)
        # deterministic vhost-ghost kill: the verify command's marker in the transcript
        # proves the vhost serves the default site -> fold dead=<vhost> so the manager
        # stops tasking exploits against a wordlist artifact (run 744 steps 3-4);
        # a REAL marker promotes the fuzz artifact to the frontier instead
        _ghost = _ghost_from_output(res.get("output"))
        _reals = _reals_from_output(res.get("output"))
        if _ghost:
            C.fold([f"dead={_ghost}"], ts=step); C.save(step)
        if _reals:
            C.fold([f"verified={r}" for r in _reals], ts=step); C.save(step)
        _via = res.get("via", "trooper")
        res["facts"] = _drop_phantoms(res["facts"])   # reject exec-host self-identity as a foothold
        dt = int(time.time() - t0)
        tel = res["telemetry"]
        # incremental surface ingestion: EVERY trooper result may reveal new ports/services/
        # versions — fold them into the map the moment they appear (the old code wrote
        # map.json at most once, so later discoveries never reached the cartographer and
        # coverage sat at 0% while the manager re-asked for the same enumeration).
        surf = _surface_to_mapjson(res["facts"], res.get("telemetry") or {}, target)
        if surf is not None and surf != last_surf:
            with open(f"{run_dir}/map.json", "w") as fh:
                json.dump(surf, fh, indent=2)
            C.ingest_map_json(step)
            C.save(step)
            ports_seeded = True
            last_surf = surf
            emit("surface", step=step,
                 ports=[p["port"] for p in surf["hosts"][0]["ports"]])
        before_hypotheses = set(C.doc.get("hypotheses", {}))
        C.fold(res["facts"], ts=step)
        C.save(step)
        # verify-at-ingestion: content-check every fuzz-born vhost NOW, so ghosts die on
        # entry instead of polluting the frontier for steps (run 745: each re-fuzz
        # re-added ~19 ghost vhosts that were never compared)
        _batch_vhost_verify(target, C, step, emit)
        # deterministic attack receipts keyed to the named app — derived from the commands
        # that ACTUALLY ran, never from a self-report (fixes the attack proof-gate)
        _af = TR._derive_attack_facts(res.get("cmds") or [], res.get("output") or "", _app,
                                      ok_flags=res.get("ok_flags"))
        if _af:
            C.fold(_af, ts=step)
            C.save(step)
        # the sanitized marker the manager will read next turn (NO raw output)
        marker = (f"observed: {str(tel.get('observed',''))[:200]} | "
                  f"blocked: {str(tel.get('blocked',''))[:160] or 'none'} | "
                  f"facts: {', '.join(str(f) for f in res['facts'])[:200] or 'none'}")
        # OPERATOR-DEBUG ONLY (P0-5): the production manager lane is CONTENT-BLIND — it
        # receives the sanitized marker, never commands or raw output. The old default
        # leaked both into every prompt, breaking the canonical manager contract. The
        # full-visibility override lives behind GB_MANAGER_RAW=1 (a named debug mode the
        # operator sets deliberately, never the default).
        if os.environ.get("GB_MANAGER_RAW", "0") == "1":
            _cmds = res.get("cmds") or []
            _cmd_lines = "\n".join(f"    $ {c}" for c in _cmds[-12:]) or "    (no commands run)"
            _tail = (res.get("output") or "")[-1800:]
            marker = (marker + "\n  RAW cmds (verify against these):\n" + _cmd_lines
                      + "\n  RAW output tail:\n"
                      + "\n".join("    " + ln for ln in _tail.splitlines()[-40:]))
        transcript.append((f"TASK {task[:200]}", marker))
        telem_history.append(f"{tel.get('observed','')} {tel.get('blocked','')}")
        for f in res["facts"]:
            if f not in seen_facts:
                seen_facts.add(f); facts.append(str(f))
        ran_event = emit("ran", step=step, secs=dt, cmds=len(res["cmds"]),
                         command=task, marker=marker, via=_via,
                         observed=str(tel.get("observed") or "")[:300],
                         fact_keys=",".join(sorted({str(f).split('=',1)[0] for f in res['facts']})) or "none",
                         blocked=str(tel.get("blocked") or "")[:160],
                         folded_facts=list(res["facts"]))
        # denial-cascade wedge breaker (run 750 + lab pass 1): N consecutive steps each
        # 100% governed-denied/blocked -> the manager is authoring doomed commands.
        # Fold exhaustion and terminate honestly instead of burning tokens on the same wall.
        _ok = res.get("ok_flags") or []
        denial_streak = denial_streak + 1 if (len(_ok) >= 1 and not any(_ok)) else 0
        if denial_streak >= 4:
            emit("stop", step=step,
                 reason="denial cascade: 4 consecutive steps fully governed-denied; folding exhaustion",
                 folded=["exhausted=denial cascade: every command governed-denied "
                         "for 4 consecutive steps"])
            C.fold(["exhausted=denial cascade: every command governed-denied for 4 consecutive steps"],
                   ts=step)
            C.save(step)
            end_kind = "stop"; break
        last_run_evidence_refs = [f"telemetry:{ran_event['seq']}"]
        for hid in sorted(set(C.doc.get("hypotheses", {})) - before_hypotheses):
            hyp = C.doc["hypotheses"][hid]
            emit("hypothesis_raised", step=step, hypothesis_id=hid,
                 vuln_class=hyp.get("vuln_class"), node=hyp.get("node"),
                 locus=hyp.get("locus"), title=hyp.get("title"),
                 confidence=hyp.get("confidence"),
                 required_validation=hyp.get("required_validation"),
                 severity=hyp.get("severity"), impact=hyp.get("impact"),
                 raised_from=["signal"], source="signal")
        # persist scrubbed state each step
        json.dump({"target": target, "facts": facts,
                   "transcript": [{"action": act, "marker": mk} for act, mk in transcript]},
                  open(f"{run_dir}/state.json", "w"), indent=1)

    # P1-6: the terminal PROJECTION — exactly one closed state, derived from the same
    # coverage report every consumer reads. A forced stop or engine stop is always
    # stopped_incomplete; missing scope blocks all complete states.
    proj = C.terminal_projection(scope={"hosts": [target]},
                                 stopped=(end_kind if end_kind in ("done_forced", "stop")
                                          else False))
    emit("final", steps_used=len([t for t in transcript if t[0].startswith('TASK')]),
         facts_n=len(facts), run_dir=run_dir,
         outcome=C.coverage_report().get("outcome"),
         objective_achieved=C.coverage_report().get("objective_achieved", False),
         projection=proj["projection"] or "blocked",
         projection_reason=proj["reason"])
    print("\n=== SCRUBBED FACTS ===")
    print("\n".join(f"- {f}" for f in facts) or "(none)")

    # --- ORDERED FIRE TIMELINE (for SOP assessment): what fired, in what order, when, how long ---
    timeline = []
    try:
        for ln in open(tpath):
            r = json.loads(ln)
            if r.get("event") == "ran":
                timeline.append(f"#{r['seq']:>2} {r['iso']}  (+{r['elapsed_s']:>5}s, {r.get('secs','?')}s)  "
                                f"{r.get('command','')}\n        -> {r.get('marker','')}")
    except Exception:
        pass
    tl_txt = "\n".join(timeline) or "(nothing fired)"
    with open(f"{run_dir}/fire_timeline.txt", "w") as fh:
        fh.write(tl_txt + "\n")
    print("\n=== FIRE TIMELINE (ordered; also in fire_timeline.txt + telemetry.jsonl) ===")
    print(tl_txt)

    # The report is a deterministic reader over battle-state plus the manager's sanitized
    # authored-command telemetry.  The manager is the caller and stamps wall-clock metadata.
    report = C.engagement_report(run_dir)
    report["generated_ts"] = int(time.time())
    report["target"] = target
    report["terminal_projection"] = proj
    with open(f"{run_dir}/report.json", "w") as fh:
        json.dump(report, fh, indent=2)
    with open(f"{run_dir}/report.md", "w") as fh:
        fh.write(CARTO_REPORT.render_markdown(report))
    emit("report", findings_by_severity=report["executive_summary"]["findings_by_severity"],
         coverage_pct=report["executive_summary"]["coverage_pct"],
         complete=report["executive_summary"]["complete"], step=a.steps,
         projection=proj["projection"] or "blocked")
    lenz.stop(step=a.steps)
    print(f"[report] wrote report.md/json | {report['completion_statement']}")
    _durable_sync(run_dir, target, final=True)
    try:
        C.experiment_ledger.save()
    except Exception:
        pass   # the experiment ledger is an optimization; a save failure never blocks the report
    _hold_session("down", sess_name)


if __name__ == "__main__":
    main()
