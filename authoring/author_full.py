#!/usr/bin/env python3
"""Full linux-service deck author. Generic, target-agnostic, blind to the box answer.
Reuses author.py's codex backend + gate. Persists raw + a deduped review queue."""
import sys, os, json, yaml, re
sys.path.insert(0, '.')
import vocab, gate, author

# Full linux-service taxonomy. Each entry -> one codex call -> ~15 generic cards.
FAMILIES = {
 "ftp-access":"FTP (21): anonymous login/listing, recursive enum, writable-dir upload-to-webroot, FTP bounce scan.",
 "ftp-cred":"FTP (21): credential brute-force (hydra/ncrack/medusa), default-cred check, cred-reuse from harvested creds.",
 "ftp-cve":"FTP: vsftpd/proftpd/pure-ftpd version->CVE lead cards (searchsploit, nmap ftp-* vuln scripts).",
 "ssh-cred":"SSH (22): credential brute (hydra), key-based auth attempts, default-cred, cred-reuse from harvested creds.",
 "ssh-enum":"SSH (22): username enumeration (CVE-2018-15473), auth-method probe, weak-algorithm/cipher audit.",
 "ssh-cve":"SSH: OpenSSH version->CVE lead cards (searchsploit, vulners).",
 "smtp-enum":"SMTP (25): user enumeration via VRFY/EXPN/RCPT, banner grab, STARTTLS probe.",
 "smtp-abuse":"SMTP (25): open-relay test (swaks), credential brute, mail-header injection probe.",
 "smtp-cve":"SMTP: Postfix/Exim/Sendmail version->CVE lead cards.",
 "dns-transfer":"DNS (53): AXFR/IXFR zone transfer (dig/dnsrecon/fierce), NS/MX/TXT record harvest.",
 "dns-brute":"DNS (53): subdomain brute (gobuster/dnsrecon/massdns/ffuf), reverse-lookup sweep.",
 "dns-info":"DNS (53): version.bind CHAOS query, cache-snooping, recursion check, DNS version->CVE leads.",
 "pop3":"POP3 (110/995 Dovecot): credential brute, cred-reuse, authenticated mailbox read for secrets/creds.",
 "imap":"IMAP (143/993 Dovecot): credential brute, cred-reuse, authenticated mailbox/folder read for secrets.",
 "mail-cve":"Mail: Dovecot/Cyrus version->CVE lead cards.",
 "http-disco":"HTTP (80/8080): content discovery (ffuf/gobuster/feroxbuster), robots.txt/.git/.env/.svn/backup files.",
 "http-vhost":"HTTP (80/8080): virtual-host brute-force, subdomain fuzzing via Host header.",
 "http-defaults":"HTTP (80/8080): default-cred check on admin panels, HTTP methods (PUT/DELETE), directory listing.",
 "http-cms":"HTTP: generic CMS detection+enum (wpscan/joomscan/droopescan) and CMS version->CVE leads.",
 "http-appserver":"HTTP: app-server known-exploit leads (Tomcat manager, Jenkins, GitLab, Struts, phpMyAdmin).",
 "http-cve":"HTTP: Apache/nginx version->CVE lead cards (searchsploit, nmap http-vuln-*, nuclei).",
 "http-injection":"HTTP: generic injection probes as leads — SQLi (sqlmap), LFI/traversal, SSTI, command-injection (blind, template-only).",
 "rpc-nfs":"RPC/NFS (111/2049): rpcinfo enumeration, showmount export listing, NFS mount + permission abuse.",
 "tls":"TLS on any port: heartbleed, weak-cipher/protocol audit, certificate CN/SAN harvest (sslscan/testssl).",
 "cred-reuse":"Cross-service credential reuse: spray a harvested credential across ssh/ftp/smtp/pop3/imap/http.",
 "px-enum":"Linux post-foothold local enum (after rce_as): sudo -l, SUID/SGID sweep, cron, capabilities, writable paths.",
 "px-gtfo":"Linux privesc leads via GTFOBins: sudo/SUID binary abuse for file-read or shell (template-only).",
 "px-kernel":"Linux privesc: kernel/distro version->exploit lead cards (linux-exploit-suggester, searchsploit uname).",
}

def clean_pred(tok):
    return re.split(r'[/\s]', str(tok).strip())[0] if tok else tok

def normalize_card(c):
    if 'confirms' in c and isinstance(c['confirms'], list):
        c['confirms'] = [clean_pred(t) for t in c['confirms']]
    v = c.get('verify')
    if isinstance(v, dict) and isinstance(v.get('emits'), list):
        v['emits'] = [clean_pred(t) for t in v['emits']]
    return c

if __name__ == "__main__":
    workdir = os.getcwd()
    pn, on = vocab.predicate_names(), vocab.operator_names()
    raw_all = []
    for fam, desc in FAMILIES.items():
        print(f"[authoring] {fam} ...", flush=True)
        try:
            cards = author.author_family(desc, 12, workdir)
        except Exception as e:
            print(f'    !! {fam} failed: {e}'); cards = []
        for c in cards:
            if isinstance(c, dict):
                c.setdefault("_family", fam)
                raw_all.append(normalize_card(c))
        print(f"    +{len(cards)} raw (total {len(raw_all)})", flush=True)
    json.dump(raw_all, open("deck_raw.json", "w"), indent=1)
    existing_deck = yaml.safe_load(open("deck_linux_service.yaml")) if os.path.exists("deck_linux_service.yaml") else []
    existing_deck = existing_deck or []
    seen, passed, rejected = {}, list(existing_deck), []
    for c in existing_deck:
        seen[gate.gate(c, pn, on)["dedup_key"]] = 1
    for c in raw_all:
        r = gate.gate(c, pn, on)
        if r["verdict"] == "PASS":
            k = r["dedup_key"]
            if k in seen: continue
            seen[k] = 1; passed.append(c)
        else:
            rejected.append({"card": c, "gate": r})
    yaml.safe_dump(passed, open("deck_linux_service.yaml", "w"), sort_keys=False)
    json.dump(rejected, open("deck_rejected.json", "w"), indent=1)
    print(f"\n=== FULL DECK ===")
    print(f"raw {len(raw_all)}  ->  PASS+dedup {len(passed)}   REJECT {len(rejected)}")
    print(f"deck -> deck_linux_service.yaml")
