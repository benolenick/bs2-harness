"""Deterministic coverage receipts: _derive_enum_facts maps executed commands to
enum=<port>:<ritual> facts (runs 739/740: the model never reports finished checks,
so the transcript is the only trustworthy source)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

from trooper import _derive_enum_facts  # noqa: E402


def test_dir_brute_receipts():
    cmds = [
        "ffuf -u http://198.51.100.10:80/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 403",
        "gobuster dir -u http://198.51.100.10:8080 -w /usr/share/wordlists/dirb/common.txt",
        "dirb http://198.51.100.10/ -r",
    ]
    facts = _derive_enum_facts(cmds)
    assert "enum=80:dirs" in facts
    assert "enum=8080:dirs" in facts


def test_vhost_and_tech_fingerprint():
    cmds = [
        "gobuster vhost -u http://198.51.100.10:80 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "ffuf -u http://198.51.100.10:80 -H 'Host: FUZZ.inlanefreight.local' -w vhosts.txt -fs 1000",
        "whatweb -a 3 http://198.51.100.10:80 http://198.51.100.10:8080",
    ]
    facts = _derive_enum_facts(cmds)
    assert "enum=80:vhosts" in facts
    assert "enum=80:tech-fingerprint" in facts
    assert "enum=8080:tech-fingerprint" in facts


def test_service_protocols():
    cmds = [
        "smtp-user-enum -M VRFY -U /usr/share/wordlists/names.txt -t 198.51.100.10",
        "dig @198.51.100.10 inlanefreight.local axfr",
        "echo -e 'user anonymous\\npass anonymous\\nls\\nbye' | ftp -n 198.51.100.10",
        "rpcinfo -p 198.51.100.10",
        "showmount -e 198.51.100.10",
        "smbclient -L //198.51.100.10 -N",
        "rpcclient -U '' -N 198.51.100.10",
        "hydra -L users.txt -P rockyou.txt ssh://198.51.100.10",
    ]
    facts = _derive_enum_facts(cmds)
    for want in ("enum=25:user-enum-vrfy", "enum=53:axfr", "enum=21:anon-login",
                 "enum=111:rpcinfo", "enum=111:nfs-shares", "enum=445:shares",
                 "enum=445:null-session", "enum=22:user-enum"):
        assert want in facts, f"missing {want} in {facts}"


def test_url_ports_win_and_flag_lists_ignored():
    # URL ports attribute precisely; -p lists are ignored (run 742 step 3: an nmap
    # -p 21,22,25,110,111,... list spread rpcinfo receipts across 110/25/143)
    cmds = ["smtp-user-enum -M VRFY -U u.txt -t 198.51.100.10 -p 2525",
            "dirb http://198.51.100.10:9090/admin -r",
            "nmap -sV -p 21,22,25,110,111,143 198.51.100.10; rpcinfo -p 198.51.100.10"]
    facts = _derive_enum_facts(cmds)
    assert "enum=25:user-enum-vrfy" in facts     # conventional port, -p 2525 ignored
    assert "enum=9090:dirs" in facts             # URL port wins
    assert "enum=111:rpcinfo" in facts           # conv port for rpcinfo
    assert "enum=21:rpcinfo" not in facts        # nmap port list NOT attributed
    assert "enum=110:rpcinfo" not in facts


def test_port_range_flag_not_read_as_port():
    # nmap "-p1-10000" is a RANGE, not port 1 (caught live on run 741 step 3)
    from trooper import _ports_of
    assert _ports_of("nmap -Pn -p1-10000 -sS --min-rate 2000 198.51.100.10") == set()
    assert "1" not in _ports_of("nmap -Pn -sC -p 111 --script nfs-showmount 198.51.100.10"
                                "; nmap -p1-10000 -sS 198.51.100.10")


def test_compound_segments_do_not_cross_contaminate():
    # run 743 step 4: capability probe + web curl in ONE compound command attributed
    # rpcinfo/nfs-shares to port 8080. Segments isolate; tool-NAME listings skip.
    # The curl -i segment now legitimately receipts tech-fingerprint (pass-7: a header
    # capture IS a fingerprint probe) — what must NOT happen is any other service's
    # receipt spreading onto 8080.
    cmd = ("id; sudo -n true 2>&1; command -v curl wget nmap ffuf gobuster hydra "
           "netexec nuclei sqlmap msfconsole smbclient showmount rpcinfo python3; "
           "echo '---8080---'; curl -sS -i --max-time 15 http://198.51.100.10:8080/ | head -120")
    facts = _derive_enum_facts([cmd])
    assert "enum=8080:tech-fingerprint" in facts
    assert not [f for f in facts if f.startswith(("enum=111", "enum=445"))]
    # the same compound WITH a real tool invocation still receipts on its own segment
    cmd2 = ("command -v ffuf rpcinfo; ffuf -u http://198.51.100.10:8080/FUZZ -w wl.txt; "
            "rpcinfo -p 198.51.100.10")
    assert _derive_enum_facts([cmd2]) == ["enum=8080:dirs", "enum=111:rpcinfo"]


def test_weak_commands_ignored_and_capped():
    cmds = ["curl -s http://198.51.100.10/", "cat /etc/passwd", "ls -la"]
    assert _derive_enum_facts(cmds) == []
    many = [f"dirb http://198.51.100.10:{p} -r" for p in range(8000, 8040)]
    assert len(_derive_enum_facts(many)) <= 10


def test_db_ldap_snmp_receipts():
    cmds = [
        "ldapsearch -x -H ldap://198.51.100.10 -b 'dc=inlanefreight,dc=local'",
        "ldapsearch -H ldap://198.51.100.10 -b '' -s base namingcontexts",
        "snmpwalk -v2c -c public 198.51.100.10",
        "onesixtyone -c community.txt 198.51.100.10",
        "mysql -h 198.51.100.10 -u root",
        "psql -h 198.51.100.10 -U postgres -W",
        "redis-cli -h 198.51.100.10 info",
        "mongosh --host 198.51.100.10 --eval 'db.version()'",
    ]
    facts = _derive_enum_facts(cmds)
    for want in ("enum=389:anonymous-bind", "enum=389:domain-info", "enum=161:snmp-walk",
                 "enum=161:community-strings", "enum=3306:anon-auth", "enum=5432:default-creds",
                 "enum=6379:no-auth", "enum=27017:no-auth"):
        assert want in facts, f"missing {want} in {facts}"


def test_mysqldump_is_not_a_mysql_client_invocation():
    # \bmysql\b must not match inside 'mysqldump' (word-boundary guard)
    assert _derive_enum_facts(["mysqldump -h 198.51.100.10 db > dump.sql"]) == []


def test_new_service_classes_have_real_rituals():
    import os, sys
    HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(HERE, "..", "live"))
    from cartographer.model import RITUALS
    for svc in ("ldap", "snmp", "mysql", "postgres", "mssql", "redis", "mongodb",
                "nfs", "rdp", "kerberos", "jira", "confluence", "elasticsearch"):
        assert RITUALS.get(svc) and RITUALS[svc] != RITUALS["_default"], f"{svc} falls back to generic enumerate"


if __name__ == "__main__":
    for fn in (test_dir_brute_receipts, test_vhost_and_tech_fingerprint,
               test_service_protocols, test_url_ports_win_and_flag_lists_ignored,
               test_port_range_flag_not_read_as_port,
               test_compound_segments_do_not_cross_contaminate,
               test_weak_commands_ignored_and_capped, test_db_ldap_snmp_receipts,
               test_mysqldump_is_not_a_mysql_client_invocation,
               test_new_service_classes_have_real_rituals):
        fn()
        print("ok", fn.__name__)
