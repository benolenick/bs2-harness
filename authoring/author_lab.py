#!/usr/bin/env python3
"""BLIND lab-terrain expansion: the 5 enterprise-lab boxes deck_final doesn't cover yet
(Windows/AD, MSSQL, IIS, Squid-proxy, web-deep) + generic heavy unauth-RCE cards.
Born with FORMAL gates: landings run `id`->uid= (rce_as); leads formal-match (vuln_present)."""
import sys, os, json, yaml, re
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0,'/opt/bs2/authoring'); sys.path.insert(0,'/opt/bs2')
import author, vocab, gate
author.MODEL_ARGS=["-m","gpt-5.6-terra"]   # frontier quality for nuanced AD/exploit cards; Ben cleared usage

PARAMS=" ".join(sorted(gate.PARAM_VOCAB))
FORMAL=r"""FORMAL GATES (mandatory — a deterministic engine parses success_if):
- success_if DSL ONLY: `exit_code ==|!= N`, `stdout|stderr contains '<lit>'`, `stdout|stderr matches '<regex>'`, joined && || and or ().
- LANDING card (invocation EXECUTES code on target): make it run `id` as proof (append '; id' / set payload cmd to id /
  webshell ...=id). success_if=`exit_code == 0 && stdout matches 'uid=\d+\('`; root-yielding: `stdout contains 'uid=0(root)'`. verify.emits=["rce_as"].
- LEAD card (only fingerprints/looks-up a vuln: searchsploit/nmap --script *-vuln/nuclei/version->CVE): NO rce claim.
  success_if=formal match on tool output (searchsploit->`stdout contains 'Exploit'`, nmap->`stdout contains 'VULNERABLE'`). verify.emits=["vuln_present"].
- CRED/hash card: gate literal secret in stdout (hash `stdout matches '\$[0-9a-zA-Z]{1,3}\$'`, ntlm `stdout matches ':[0-9a-f]{32}'`). emits ["has_hash"] or ["controls_principal"].
- emits ONLY from: rce_as, controls_principal, has_hash, vuln_present, known_exploit, pwn_host."""
RULES=f"""HARD RULES:
- GENERIC + BLIND: never a specific host/flag/filename/answer. Templates only. Use ONLY these vars: {PARAMS}.
- Content-blind: invocation is a TOOL INVOCATION template, not an embedded payload/flag.
- confirms:/verify.emits use ONLY predicate NAMES from VOCAB (no /arity). operator: reuse a listed Ariadne op or "".
- DEFAULT/ANON creds: hardcode them (sa:blank, guest, anonymous) — don't template a known-credential card.
- TOOL REDUNDANCY: multiple cards per technique with DIFFERENT common tools (nxc AND impacket AND ldapsearch; etc).
{FORMAL}"""
def build_prompt(desc,n):
    return (f"{author.SCHEMA_HINT}\n{RULES}\n\n{author.EXAMPLE_CARD}\n\n"
            f"VOCAB (only legal predicate/operator names):\n{vocab.llm_vocab_block()}\n\n"
            f"FAMILY: {desc}\n\nEmit {n} distinct GENERIC cards covering this family broadly. "
            f"JSON array only, no prose/fences.")
FAMILIES={
 "ad-ldap-anon":"Active Directory LDAP anonymous/null bind enumeration: naming context, users, groups, computers, descriptions (ldapsearch, nxc ldap, windapsearch).",
 "ad-smb-null":"AD SMB null/guest session enum: shares, users via RID cycling, password policy (enum4linux-ng, nxc smb, smbclient, rpcclient).",
 "ad-user-enum":"AD Kerberos username enumeration + valid-user discovery (kerbrute userenum, nmap krb5-enum-users).",
 "ad-asrep":"AS-REP roasting for accounts w/o preauth -> krb5asrep hash (impacket GetNPUsers, nxc). CRED phase.",
 "ad-kerberoast":"Kerberoasting service accounts -> krb5tgs hash (impacket GetUserSPNs, nxc). CRED phase.",
 "ad-passwordspray":"AD low-and-slow password spray over SMB/Kerberos -> valid creds (nxc smb, kerbrute passwordspray).",
 "ad-winrm-exec":"WinRM authenticated command execution proving RCE (evil-winrm, nxc winrm -x id). LANDING.",
 "ad-rdp":"RDP NLA/cred validation + ntlm-info (xfreerdp, nxc rdp, nmap rdp-ntlm-info).",
 "ad-bloodhound":"BloodHound collection over LDAP for attack-path graph (bloodhound-python, nxc --bloodhound).",
 "ad-smb-vuln":"SMB remote-vuln leads: ms17-010/zerologon/petitpotam (nmap smb-vuln*, nxc). LEAD.",
 "ad-rpc-enum":"MS-RPC endpoint + SAMR enumeration (impacket rpcdump, samrdump, rpcclient).",
 "ad-adcs":"ADCS certificate-template abuse enumeration ESC1-ESC8 leads (certipy find). LEAD.",
 "ad-secretsdump":"Post-cred domain/local secret extraction -> hashes (impacket secretsdump, nxc --sam --lsa). CRED.",
 "ad-gpp":"SYSVOL Group-Policy-Preferences cpassword harvest -> cleartext cred (nxc, gpp-decrypt). CRED.",
 "mssql-enum":"MSSQL instance enumeration + ntlm-info (nmap ms-sql-info/ms-sql-ntlm-info, nxc mssql).",
 "mssql-brute":"MSSQL default sa/blank + credential brute -> valid login (nxc mssql, hydra, medusa).",
 "mssql-xpcmd":"MSSQL xp_cmdshell / ole-automation command exec proving RCE (impacket mssqlclient -> id). LANDING.",
 "mssql-linked":"MSSQL linked-server enumeration + exec pivot (impacket mssqlclient EXECUTE AT).",
 "mssql-cve":"MSSQL version->CVE lead (searchsploit, nmap). LEAD.",
 "iis-enum":"IIS discovery: tilde shortname, handlers/extensions, WebDAV OPTIONS, aspx (shortscan, davtest, curl).",
 "iis-webdav-rce":"IIS/WebDAV PUT/MOVE webshell upload proving RCE (davtest, cadaver, curl PUT -> aspx?cmd=id). LANDING.",
 "aspnet-viewstate":"ASP.NET __VIEWSTATE MAC-key deserialization lead (ysoserial.net, viewstate). LEAD.",
 "squid-enum":"Squid proxy fingerprint + cachemgr/cachemgr.cgi access + version (curl, nmap http-*).",
 "squid-proxy-abuse":"Abuse Squid as open proxy to reach/scan internal services (curl -x, proxychains, nmap through proxy).",
 "squid-cve":"Squid version->CVE lead (searchsploit, nuclei). LEAD.",
 "web-git-exposure":"Exposed VCS/config leak: .git/.env/.svn/backup archives -> creds/source (git-dumper, curl, wget). LOOT/CRED.",
 "web-apache-traversal-rce":"Apache 2.4.49/50 path-traversal to RCE CVE-2021-41773/42013 (curl cgi-bin -> id). LANDING.",
 "web-nginx-misconfig":"Nginx alias/off-by-slash traversal + merge_slashes discovery (ffuf, curl).",
 "rce-gitlab-22205":"GitLab unauth RCE CVE-2021-22205 via ExifTool DjVu on any GitLab<=13.10.2 (drop payload running id -> uid=). Generic service-class LANDING.",
 "rce-struts2":"Apache Struts2 OGNL RCE S2-045/S2-046/S2-052 on any vulnerable Struts app (curl Content-Type payload -> id). LANDING.",
 "rce-drupalgeddon2":"Drupal CVE-2018-7600 unauth RCE on any vulnerable Drupal (curl form-array payload -> id). LANDING.",
 "rce-tomcat-manager":"Tomcat manager/host-manager default-cred war deploy -> RCE (curl PUT war -> jsp?cmd=id). LANDING.",
 "rce-jenkins":"Jenkins script-console / unauth CVE RCE on any vulnerable Jenkins (curl scriptText -> id). LANDING.",
 "log4shell-probe":"Log4Shell CVE-2021-44228 JNDI injection probe across headers/params (nuclei log4j, curl callback). LEAD.",
}
def run_family(name,desc,n,wd):
    try:
        cards=author.author_family(desc,n,wd) or []
        good=[]
        for c in cards:
            if not isinstance(c,dict): continue
            c["_family"]=name
            g=gate.gate(c, vocab.predicate_names(), vocab.operator_names())
            if g["verdict"]!="REJECT": good.append(c)
        return name,good,len(cards)
    except Exception as e:
        return name,[],f"ERR:{e}"
def main():
    wd="/tmp/claude-1000/-home-om/067fda82-0b60-4e34-84fb-abc54359c68c/scratchpad/lab"
    os.makedirs(wd,exist_ok=True)
    N=8; all_cards=[]; log={}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs={ex.submit(run_family,n,d,N,wd):n for n,d in FAMILIES.items()}
        for f in as_completed(futs):
            name,good,raw=f.result()
            log[name]=f"{len(good)} kept / {raw} raw"
            all_cards.extend(good)
            print(f"[{name}] {log[name]}  (running total {len(all_cards)})")
    yaml.safe_dump(all_cards, open("/opt/bs2/authoring/deck_lab.yaml","w"), sort_keys=False)
    print(f"\nDONE: {len(all_cards)} lab cards -> deck_lab.yaml across {len(FAMILIES)} families")
main()
