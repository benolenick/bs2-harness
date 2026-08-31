"""Regression tests for the surface parsers in manager/run_htb.py.

Fixtures are REAL data from run 733 (198.51.100.10, 2026-08-25): the trooper's observed
telemetry string, and a representative nmap -oG output. These parsers are what feed
discovered services/versions into the cartographer map — before they existed, coverage
sat at 0% while the manager re-issued the same enumeration task.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "manager"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "live"))

from run_htb import _surface_to_mapjson, _gnmap_ports, _gnmap_surface  # noqa: E402

# actual observed telemetry from run 733 step 1
OBS = ("198.51.100.10: 21/vsftpd3.0.3, 22/OpenSSH8.2p1Ubuntu-4ubuntu0.5, 25/Postfix, "
       "53/DNS-banner-1337_HTB_DNS, 80/Apache2.4.41, 110/Dovecot-pop3d, 111/rpcbind2-4, "
       "143/Dovecot-imapd, 993/Dovecot-imaps, 995/Dovecot-pop3s, 8080/Apache2.4.41")


def test_observed_telemetry_becomes_map():
    surf = _surface_to_mapjson([], {"observed": OBS}, "198.51.100.10")
    ports = {p["port"]: (p["name"], p["product"], p["version"])
             for p in surf["hosts"][0]["ports"]}
    assert ports[21] == ("ftp", "vsftpd", "3.0.3")
    assert ports[22] == ("ssh", "OpenSSH8.2p1Ubuntu-4ubuntu0.5", "")   # no fake version
    assert ports[25] == ("smtp", "Postfix", "")
    assert ports[53] == ("dns", "DNS-banner-1337_HTB_DNS", "")
    assert ports[80] == ("http", "Apache", "2.4.41")
    assert ports[110][0] == "pop3"      # Dovecot-pop3d is pop3, not imap
    assert ports[111][0] == "rpcbind"
    assert ports[143][0] == "imap"
    assert ports[993][0] == "imap"
    assert ports[995][0] == "pop3"      # Dovecot-pop3s: the 3 is protocol, not version
    assert ports[8080][1] == "Apache"


def test_facts_path_seeds_and_enriches():
    surf = _surface_to_mapjson(["ports=21,80", "web80=Apache 2.4.41"], {}, "1.2.3.4")
    ports = {p["port"]: p for p in surf["hosts"][0]["ports"]}
    assert ports[80] == {"port": 80, "name": "http", "product": "Apache 2.4.41",
                         "version": "2.4.41"}
    assert ports[21]["name"] == "ftp"


def test_observed_enriches_facts_entry():
    surf = _surface_to_mapjson(["ports=80"], {"observed": "80/Apache2.4.41"}, "1.2.3.4")
    assert surf["hosts"][0]["ports"][0] == {"port": 80, "name": "http",
                                            "product": "Apache", "version": "2.4.41"}


GNMAP = ("Host: 1.2.3.4 () Ports: "
         "21/open/tcp//ftp//vsftpd 3.0.3///, "
         "80/open/tcp//http//Apache httpd 2.4.41 ((Ubuntu))///, "
         "23/closed/tcp/////")


def test_gnmap_ports():
    assert _gnmap_ports(GNMAP) == [21, 80]


def test_gnmap_surface():
    gv = _gnmap_surface(GNMAP, "1.2.3.4")
    ports = gv["hosts"][0]["ports"]
    assert ports[0] == {"port": 21, "name": "ftp", "product": "vsftpd 3.0.3",
                        "version": "3.0.3"}
    assert ports[1]["name"] == "http"
    assert ports[1]["version"] == "2.4.41"


def test_vhost_verify_hint():
    from run_htb import _vhost_verify_hint

    class Cart:
        doc = {"nodes": {
            "vhost:gitlab.inlanefreight.local": {"kind": "vhost", "label": "gitlab.inlanefreight.local"},
            "vhost:h.inlanefreight.local": {"kind": "vhost", "label": "h.inlanefreight.local"},
        }}

    task = "Fire the matching exploit for gitlab.inlanefreight.local on port 80"
    hint = _vhost_verify_hint(task, "198.51.100.10", Cart())
    assert hint, "vhost mention must yield a verify hint"
    assert "Host: gitlab.inlanefreight.local" in hint
    assert "VHOST_GHOST_SAME_CONTENT" in hint
    # no vhost mentioned -> no hint; no cart -> no hint
    assert _vhost_verify_hint("Enumerate web apps on ports 80 and 8080", "198.51.100.10", Cart()) is None
    assert _vhost_verify_hint("fire it", "198.51.100.10", None) is None


def test_ghost_from_output():
    from run_htb import _ghost_from_output
    out = ("$ curl -s -o /tmp/gb_vh_default http://198.51.100.10/ -w 'DEFAULT_SIZE=%{size_download}\\n'; "
           "curl -s -o /tmp/gb_vh_candidate -H 'Host: ir.inlanefreight.local' http://198.51.100.10/ "
           "-w 'VHOST_SIZE=%{size_download}\\n'; cmp -s ... && echo VHOST_GHOST_SAME_CONTENT || "
           "echo VHOST_REAL_DISTINCT\n"
           "DEFAULT_SIZE=15157\nVHOST_SIZE=15157\nVHOST_GHOST_SAME_CONTENT")
    assert _ghost_from_output(out) == "ir.inlanefreight.local"
    # no marker -> None even with a Host header present
    assert _ghost_from_output("curl -H 'Host: x.inlanefreight.local' http://t/") is None
    assert _ghost_from_output("") is None
