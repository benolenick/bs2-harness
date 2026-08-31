#!/usr/bin/env python3
"""Exhaustive BLIND corpus slice for the linux-service box class (redmirror / HTB ent box1).
Covers every sector the box presents, generic + answer-free. Concurrent codex authoring.
Writes to deck_slice.yaml (separate from the running deck to avoid a merge race)."""
import sys, os, json, yaml, re
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, '/opt/bs2/authoring')
import vocab, gate, author

PARAMS = " ".join(sorted(gate.PARAM_VOCAB))

RULES = f"""HARD RULES:
- GENERIC + BLIND. Never reference a specific host, flag, filename, or known answer. Templates only.
- Content-blind: invocation is a TOOL INVOCATION template, never an embedded payload/flag/loot.
- confirms:/verify.emits MUST use ONLY predicate NAMES from the VOCAB (no /arity suffix). Else [].
- operator: reuse a listed Ariadne operator; else "".
- TEMPLATE VARS: use ONLY these canonical names: {PARAMS}.
- ANON/DEFAULT-CRED cards: HARDCODE the credential (anonymous:anonymous, admin:admin) — do NOT
  template {{{{user}}}}/{{{{password}}}} on a card whose whole point is a known/blank credential.
- TOOL REDUNDANCY: emit multiple cards per technique using DIFFERENT common tools (curl AND lftp AND
  wget for FTP; ffuf AND gobuster AND feroxbuster for dirs). Whichever the executor has installed wins.
- Provide a real verify.success_if (two-channel: in-band response OR out-of-band callback).
- Include version->CVE 'lead' cards (searchsploit/nmap-vuln-scripts/nuclei) tiered 'standard'."""

def build_prompt(desc, n):
    return (f"{author.SCHEMA_HINT}\n{RULES}\n\n{author.EXAMPLE_CARD}\n\n"
            f"VOCAB (only legal predicate/operator names):\n{vocab.llm_vocab_block()}\n\n"
            f"FAMILY TO COVER: {desc}\n\nEmit {n} distinct GENERIC cards covering this family broadly. "
            f"Output ONLY a JSON array of card objects. No prose, no fences.")

FAMILIES = {
 # ---- FTP ----
 "ftp-anon":"FTP anonymous access: login+listing, recursive enum, writable-dir upload to webroot (curl/lftp/wget/ftp variants).",
 "ftp-brute":"FTP credential brute-force + default creds (hydra, ncrack, medusa, patator variants).",
 "ftp-adv":"FTP advanced: FTP bounce scan, FTPS/implicit-TLS, PASV abuse.",
 "ftp-cve":"FTP version->CVE leads: vsftpd, proftpd, pure-ftpd, filezilla (searchsploit + nmap ftp-* vuln scripts).",
 # ---- SSH ----
 "ssh-brute":"SSH credential brute-force + default creds + key-based attempts (hydra, ncrack, medusa).",
 "ssh-enum":"SSH username enumeration (CVE-2018-15473), auth-method probe, none-auth probe, banner grab.",
 "ssh-crypto":"SSH weak cipher/kex/MAC audit and host-key harvest (ssh-audit, nmap ssh2-enum-algos).",
 "ssh-cve":"SSH OpenSSH/dropbear version->CVE leads (searchsploit, vulners).",
 # ---- SMTP ----
 "smtp-enum":"SMTP user enumeration VRFY/EXPN/RCPT (smtp-user-enum, nmap smtp-enum-users, manual).",
 "smtp-relay":"SMTP open-relay test + mail spoofing/header-injection probe (swaks, nmap smtp-open-relay).",
 "smtp-brute":"SMTP AUTH credential brute + STARTTLS downgrade probe.",
 "smtp-cve":"SMTP Postfix/Exim/Sendmail version->CVE leads (esp Exim CVE-2019-10149 class).",
 # ---- DNS ----
 "dns-xfer":"DNS zone transfer AXFR/IXFR (dig, dnsrecon, fierce, host); NS/MX/TXT harvest.",
 "dns-brute":"DNS subdomain brute-force (gobuster, ffuf, dnsrecon, massdns, amass, puredns).",
 "dns-info":"DNS version.bind CHAOS query, recursion check, cache snooping, reverse-lookup sweep.",
 "dns-sec":"DNS DNSSEC/NSEC(3) zone walking (ldns-walk, nsec3walker).",
 "dns-cve":"DNS BIND/dnsmasq/PowerDNS version->CVE leads.",
 # ---- POP3 / IMAP mail ----
 "pop3-auth":"POP3 credential brute + default/reuse creds + authenticated mailbox read for secrets.",
 "imap-auth":"IMAP credential brute + default/reuse creds + authenticated folder/mailbox read for secrets.",
 "mail-cve":"Dovecot/Cyrus/Courier version->CVE leads.",
 # ---- HTTP: discovery ----
 "http-dirs":"HTTP directory/content discovery (ffuf, gobuster, feroxbuster, dirb, dirsearch variants).",
 "http-vhost":"HTTP virtual-host / Host-header fuzzing (ffuf, gobuster vhost).",
 "http-files":"HTTP sensitive files: robots.txt, sitemap, .git/.svn/.hg, .env, backup archives, .DS_Store.",
 "http-methods":"HTTP method abuse (PUT/DELETE/TRACE/WebDAV), dir-listing, options probe.",
 # ---- HTTP: fingerprint/leads ----
 "http-fp":"HTTP fingerprinting (whatweb, wappalyzer, nmap http-* headers) feeding version->CVE leads.",
 "http-apache":"Apache httpd version->CVE leads (searchsploit, nmap http-vuln-*, nuclei).",
 "http-nginx":"nginx version->CVE + misconfig leads (alias traversal, merge_slashes).",
 # ---- HTTP: injection/probes ----
 "http-sqli":"Web SQL injection probes + dump (sqlmap generic, manual error/union/blind) as leads.",
 "http-lfi":"Web LFI/path-traversal + log/wrapper RCE probes (generic, template-only).",
 "http-ssti":"Web SSTI probes across engines (jinja/twig/freemarker) as detection leads.",
 "http-xxe":"Web XXE probes (file read, SSRF via entity) template-only.",
 "http-cmdi":"Web OS command-injection probes (blind + time-based) template-only.",
 "http-upload":"Web arbitrary file-upload probes (webshell ext bypass) template-only.",
 "http-authbypass":"Web auth bypass: default creds, weak session, JWT none-alg, SQL auth bypass.",
 "http-idor":"Web IDOR/BOLA + mass-assignment + forced-browsing probes.",
 "http-ssrf":"Web SSRF probes (cloud metadata, internal port scan) template-only.",
 "http-cors":"Web CORS misconfig + clickjacking + open-redirect probes.",
 "http-graphql":"GraphQL introspection + injection probes.",
 "http-api":"REST API enumeration: swagger/openapi, actuator, wp-json, common API paths.",
 # ---- HTTP: apps/CMS ----
 "cms-wordpress":"WordPress detection+enum+CVE leads (wpscan, users, plugins, xmlrpc).",
 "cms-joomla":"Joomla detection+enum+CVE leads (joomscan, droopescan).",
 "cms-drupal":"Drupal detection+enum+CVE leads (droopescan, drupwn, Drupalgeddon class).",
 "app-tomcat":"Apache Tomcat manager default-creds + WAR deploy + CVE leads.",
 "app-jenkins":"Jenkins unauth script-console + CVE leads.",
 "app-gitlab":"GitLab version->CVE leads (incl CVE-2021-22205 exiftool RCE class).",
 "app-phpmyadmin":"phpMyAdmin default-creds + LFI/CVE leads.",
 "app-struts":"Apache Struts OGNL/CVE leads.",
 # ---- RPC / NFS ----
 "rpc-nfs":"RPC/NFS enum + abuse: rpcinfo, showmount, nfs mount, no_root_squash, uid-spoof file read/write.",
 # ---- TLS ----
 "tls":"TLS audit: heartbleed, weak cipher/protocol, cert CN/SAN harvest, STARTTLS (sslscan/testssl/openssl).",
 # ---- credential reuse ----
 "cred-reuse":"Cross-service credential spray: reuse a harvested credential across ssh/ftp/smtp/pop3/imap/http.",
 # ---- Linux post-exploitation (after foothold, rce_as) ----
 "px-enum-basic":"Linux local enum after foothold: id, sudo -l, /etc/passwd, cron, listening ports, running procs.",
 "px-suid":"Linux SUID/SGID discovery + abuse leads (find perm, GTFOBins SUID shell/file-read).",
 "px-sudo":"Linux sudo misconfig abuse leads (sudo -l, GTFOBins sudo, LD_PRELOAD via env_keep, sudo CVE).",
 "px-cron":"Linux cron/systemd-timer abuse: writable cron scripts, PATH hijack, wildcard injection.",
 "px-caps":"Linux capabilities abuse (getcap, cap_setuid, cap_dac_read_search leads).",
 "px-writable":"Linux writable-path privesc: /etc/passwd writable, writable service unit, PATH hijack.",
 "px-creds":"Linux credential looting: config files, history, ssh keys, env, db creds, backup files.",
 "px-kernel":"Linux kernel/distro version->exploit leads (linux-exploit-suggester, searchsploit uname, dirtypipe/pwnkit class).",
 "px-docker":"Linux container/docker/lxc escape leads (docker sock, privileged, GTFOBins docker).",
 "px-nfs-root":"Linux NFS no_root_squash local->root via crafted SUID (leads).",
 "px-path-hijack":"Linux relative-PATH / library (LD_PRELOAD, LD_LIBRARY_PATH, python/ruby path) hijack leads.",
}

def do(fam_desc):
    fam, desc = fam_desc
    try:
        cards = author.author_family(desc, 15, "/opt/bs2/authoring")
        for c in cards:
            if isinstance(c, dict): c.setdefault("_family", fam)
        return fam, [c for c in cards if isinstance(c, dict)]
    except Exception as e:
        return fam, []

def main():
    pn, on = vocab.predicate_names(), vocab.operator_names()
    # monkeypatch author.build_prompt to use our improved prompt
    author.build_prompt = build_prompt
    raw_all = []
    done = 0
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(do, item): item[0] for item in FAMILIES.items()}
        for f in as_completed(futs):
            fam, cards = f.result(); raw_all += cards; done += 1
            print(f"[{done}/{len(FAMILIES)}] {fam}: +{len(cards)} (raw {len(raw_all)})", flush=True)
    json.dump(raw_all, open("slice_raw.json","w"))
    seen, passed, rej = {}, [], 0
    for c in raw_all:
        r = gate.gate(c, pn, on)
        if r["verdict"]=="PASS":
            k=r["dedup_key"]
            if k in seen: continue
            seen[k]=1; passed.append(c)
        else: rej += 1
    yaml.safe_dump(passed, open("deck_slice.yaml","w"), sort_keys=False)
    print(f"\n=== SLICE: raw {len(raw_all)} -> PASS+dedup {len(passed)} (rej {rej}) -> deck_slice.yaml ===")

if __name__ == "__main__":
    main()
