"""Cartographer lifecycle model and node helpers."""

from __future__ import annotations


LEDGER = "cartography.json"

# ---- lifecycle states -------------------------------------------------------
UNTOUCHED   = "untouched"      # discovered, nothing enumerated yet          -> on frontier (full payoff)
ENUMERATING = "enumerating"    # some rituals run, not all                   -> on frontier (reduced)
EXHAUSTED   = "exhausted"      # every discovery ritual run, nothing left    -> off frontier
FOOTHOLD    = "led-to-foothold"# this node produced code-exec / a cred       -> off frontier
DEAD        = "dead"           # confirmed a dead end (denied/closed/patched)-> off frontier
UNVERIFIED  = "unverified"     # fuzz artifact, not content-checked yet (vhost wordlist hits)
                               # -> OFF frontier: a ghost until proven to serve distinct content
OFF_FRONTIER = {EXHAUSTED, FOOTHOLD, DEAD, UNVERIFIED}

# ---- discovery rituals: what a real pentester ALWAYS checks, per kind --------
# Data, not decisions. These are the enumeration classes; the manager authors the actual command.
RITUALS = {
    "http":   ["dirs", "vhosts", "params", "tech-fingerprint", "default-creds",
               "js-endpoints", "api-surface", "source-exposure", "cloud-exposure", "auth-crawl"],
    "https":  ["dirs", "vhosts", "params", "tech-fingerprint", "default-creds",
               "js-endpoints", "api-surface", "source-exposure", "cloud-exposure", "auth-crawl"],
    "ftp":    ["anon-login", "version-cve"],
    "smb":    ["shares", "users", "null-session"],
    "ssh":    ["version-cve", "user-enum"],
    "smtp":   ["user-enum-vrfy"],
    "dns":    ["axfr", "subdomain-brute"],
    "pop3":   ["creds-if-known"],
    "imap":   ["creds-if-known"],
    "rpcbind":["rpcinfo", "nfs-shares"],
    # ---- service classes that previously fell back to generic ["enumerate"] ----
    "ldap":    ["anonymous-bind", "domain-users", "domain-info"],
    "snmp":    ["community-strings", "snmp-walk"],
    "mysql":   ["anon-auth", "version-cve", "default-creds"],
    "postgres":["anon-auth", "version-cve", "default-creds"],
    "mssql":   ["anon-auth", "version-cve", "default-creds"],
    "redis":   ["no-auth", "version-cve"],
    "mongodb": ["no-auth", "version-cve"],
    "nfs":     ["nfs-shares", "export-perms"],
    "rdp":     ["version-cve", "creds-if-known"],
    "kerberos":["asrep-roast", "user-enum"],
    "jira":    ["version-cve", "default-creds"],
    "confluence": ["version-cve", "default-creds"],
    "elasticsearch": ["version-cve", "default-creds"],
    "app":    ["cve-lookup", "default-creds", "known-exploit-chain"],
    "endpoint":["params-fuzz", "authz-diff", "injection-signals",
                "js-endpoints", "api-surface", "params"],
    "vhost":  ["treat-as-new-web-surface"],
    "cred":   ["spray-across-services", "auth-to-app"],
    "host":   ["full-port-sweep", "internal-ports-if-shell",
               "passive-dns", "subdomain-discovery", "cert-infra"],
    "share":  ["list-files", "writable-check"],
    "user":   ["as-spray-target", "kerberoast-if-ad"],
    # ---- interior (post-foothold) discovery frontier: OPENED when a host reaches FOOTHOLD -----
    "identity": ["whoami-privs", "sudo-rights", "group-memberships"],
    "localenum":["local-services", "listening-ports", "config-secrets",
                 "interesting-files", "installed-software"],
    "privesc":  ["suid-sgid", "cron-jobs", "writable-paths", "kernel-version", "password-reuse"],
    "netview":  ["interfaces-subnets", "arp-neighbors", "reachable-hosts", "routing"],
    "session":  [],   # a session is a durable fact (a foothold/pivot), not an enumeration target
    "_default":["enumerate"],
}

# Short, tool-agnostic meanings for the discovery classes the manager may see.
# This is guidance only: the manager still authors every concrete command.
RITUAL_GUIDE = {
    "vhosts": "brute virtual-host names against the web port (gobuster vhost / ffuf Host header).",
    "js-endpoints": "fetch the app's JS, extract referenced endpoints/paths and any embedded secrets/keys.",
    "api-surface": "look for OpenAPI/Swagger/GraphQL descriptors and enumerate the API surface.",
    "source-exposure": "check for exposed VCS/backup artifacts (.git/.svn/.bak/archive) that leak source.",
    "cloud-exposure": "look for cloud/storage references (S3/blob/bucket URLs) and test public exposure.",
    "auth-crawl": "once you hold valid creds, crawl the authenticated surface for new endpoints/roles.",
    "passive-dns": "gather domains/subdomains from passive sources without touching the target.",
    "subdomain-discovery": "enumerate subdomains (passive + bruteforce) and fold new web roots.",
    "cert-infra": "harvest TLS certificate SANs/issuer for additional hostnames/infrastructure.",
    "params": "enumerate request parameters on the endpoint (hidden fields, fuzzing) for injection points.",
    "dirs": "enumerate common and application-specific paths and files on the web root.",
    "tech-fingerprint": "identify the web stack, frameworks, components, and versions from observable clues.",
    "default-creds": "check documented default credentials for the identified product without broad guessing.",
    "cve-lookup": "research known vulnerabilities for the identified product and version, then validate safely.",
    "shares": "enumerate available file shares and their access permissions.",
    "axfr": "test whether an authoritative DNS server permits a zone transfer.",
    "anon-login": "test whether the service permits anonymous access and enumerate exposed content.",
    "users": "enumerate exposed account names through service-supported, bounded methods.",
    "user-enum": "enumerate valid usernames via service-supported, bounded methods (no broad guessing).",
    "version-cve": "identify the service version and research applicable known vulnerabilities.",
    # ---- the formerly-generic service classes ----
    "anonymous-bind": "attempt an unauthenticated/anonymous LDAP bind and read the base directory.",
    "domain-users": "enumerate directory users/groups via bounded LDAP queries.",
    "domain-info": "read directory metadata (naming contexts, schema, trust relationships).",
    "community-strings": "test well-known SNMP community strings for read access.",
    "snmp-walk": "walk the SNMP MIB for system info, interfaces, users, and processes.",
    "anon-auth": "test whether the database accepts anonymous/empty credentials and what it exposes.",
    "no-auth": "test whether the store requires authentication at all and enumerate exposed data.",
    "export-perms": "check which NFS exports are mountable/writable and what they expose.",
    "asrep-roast": "enumerate AS-REP-roastable accounts (Kerberos pre-auth disabled).",
    "rpcinfo": "enumerate registered RPC programs and the services they expose.",
    # ---- interior / post-foothold classes -----------------------------------
    "whoami-privs": "establish the current user, its uid/gid and effective privileges on the host.",
    "sudo-rights": "check what the current user may run via sudo and whether any path is abusable.",
    "group-memberships": "list group memberships that may grant extra access (docker, adm, lxd, wheel).",
    "local-services": "enumerate locally-running services and daemons not exposed externally.",
    "listening-ports": "list locally-bound ports to reveal internal-only services worth pivoting to.",
    "config-secrets": "search readable config files for credentials, tokens, and connection strings.",
    "interesting-files": "look for readable secrets, histories, keys, and backups in home/app dirs.",
    "installed-software": "inventory installed packages/versions to spot locally-exploitable components.",
    "suid-sgid": "list SUID/SGID binaries and check GTFOBins for a privilege-escalation primitive.",
    "cron-jobs": "enumerate scheduled tasks and check for writable scripts or wildcards you control.",
    "writable-paths": "find world/group-writable files or PATH entries that a privileged context executes.",
    "kernel-version": "record the kernel/OS build and research applicable local privilege-escalation.",
    "password-reuse": "test recovered credentials against local accounts and other reachable services.",
    "interfaces-subnets": "read local interfaces/routes to discover additional subnets to pivot into.",
    "arp-neighbors": "read the ARP/neighbor table for live internal hosts already talking to this one.",
    "reachable-hosts": "probe which internal hosts/ports are reachable from this foothold for pivoting.",
    "routing": "read the routing table to understand which networks this host can reach.",
}


def guide_for(classes):
    """Return distinct ``(class, guidance)`` pairs in frontier order."""
    guided = []
    seen = set()
    for ritual in classes or []:
        if ritual in seen:
            continue
        seen.add(ritual)
        guide = RITUAL_GUIDE.get(ritual)
        if guide:
            guided.append((ritual, guide))
    return guided

# base payoff by kind/service (a real operator's instinct: apps & creds first, ssh last)
PAYOFF = {
    "app": 100, "cred": 95, "vhost": 78, "http": 80, "https": 82, "endpoint": 70,
    "smb": 66, "share": 64, "ftp": 55, "dns": 50, "rpcbind": 46, "smtp": 40,
    "user": 44, "pop3": 30, "imap": 30, "host": 60, "ssh": 20,
    # interior post-foothold work: privesc + identity first, then local recon + pivot view
    "privesc": 92, "identity": 76, "localenum": 72, "netview": 68, "session": 0,
    "_default": 45,
}
STATE_MULT = {UNTOUCHED: 1.0, ENUMERATING: 0.5}   # others are off-frontier


def _node(doc, nid, kind, label, parent=None, opened_by="", meta=None, ts=0, state=None):
    n = doc["nodes"].get(nid)
    if n is None:
        n = {"id": nid, "kind": kind, "label": label, "parent": parent,
             "state": state or UNTOUCHED, "opened_by": opened_by, "meta": meta or {},
             "rituals_done": [], "created_ts": ts, "touched_ts": 0, "notes": []}
        doc["nodes"][nid] = n
    else:
        # enrich existing node without clobbering its lifecycle
        if label and len(label) > len(n.get("label") or ""):
            n["label"] = label
        if meta:
            n["meta"].update(meta)
    return n


def _rituals_for(n):
    if n["kind"] == "port":
        return RITUALS.get(n["meta"].get("service", ""), RITUALS["_default"])
    return RITUALS.get(n["kind"], RITUALS["_default"])


def _recompute_state(n, ts):
    if n["state"] in OFF_FRONTIER:
        return
    rituals = _rituals_for(n)
    done = set(n.get("rituals_done") or [])
    if rituals and done >= set(rituals):
        n["state"] = EXHAUSTED
    elif done:
        n["state"] = ENUMERATING
    n["touched_ts"] = ts


def _match(doc, hint):
    """fuzzy-match a free-text hint to existing node ids (for state-transition obs)."""
    h = str(hint).lower()
    hits = []
    for nid, n in doc["nodes"].items():
        hay = f"{nid} {n.get('label','')} {n['meta'].get('service','')} {n['meta'].get('product','')}".lower()
        if h and (h in hay or nid.lower().endswith(":" + h) or h in nid.lower()):
            hits.append(nid)
    if h.isdigit() and len(hits) > 1:
        # a bare numeric hint means a PORT: prefer the exact port match over substring
        # hits ("21" must not mark port 2121's node)
        exact = [nid for nid in hits
                 if str(doc["nodes"][nid].get("meta", {}).get("port")) == h]
        if exact:
            hits = exact
    # prefer the most specific (longest id) match
    return sorted(hits, key=len, reverse=True)


def _match_exact(doc, hint):
    """EXACT-OR-UNAMBIGUOUS node resolution for lifecycle-control observations
    (enum=/attack=/verified=/done=/dead=). A state transition must bind a stable node:
    an exact node id always wins; otherwise the hint must resolve to exactly ONE node
    by (a) exact id-suffix segment, (b) exact label equality, or (c) exact numeric port.
    Zero or multiple candidates FAIL CLOSED — unknown or ambiguous observations must not
    mutate anything (critique #4: fuzzy first-match can update the wrong node)."""
    h = str(hint).strip().lower()
    if not h:
        return []
    if h in doc["nodes"]:
        return [h]
    cands = set()
    for nid, n in doc["nodes"].items():
        if nid.lower().endswith(":" + h) or str(n.get("label", "")).strip().lower() == h:
            cands.add(nid)
        elif h.isdigit() and str(n.get("meta", {}).get("port")) == h:
            cands.add(nid)
    return [next(iter(cands))] if len(cands) == 1 else []


__all__ = [
    "LEDGER",
    "UNTOUCHED",
    "ENUMERATING",
    "EXHAUSTED",
    "FOOTHOLD",
    "DEAD",
    "UNVERIFIED",
    "OFF_FRONTIER",
    "RITUALS",
    "RITUAL_GUIDE",
    "guide_for",
    "PAYOFF",
    "STATE_MULT",
]
