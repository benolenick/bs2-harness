#!/usr/bin/env python3
"""target_exec — the single, physically-exclusive target-contact primitive (§10.1).

BS2-CONTROL-SYSTEM-CRITIQUE.md §10.1: "Execution is not physically exclusive. Direct Bash,
SSH, subprocess, recipe, hands, specialist, and launcher paths can touch the target outside
one governed adapter." This module is the fix: EVERY target-facing command in gunbelt runs
through `run()` here and nowhere else. Collapsing recipes.sh(), trooper.run_cmd(),
hands._jagg(), and the engine onto this one function is what makes execution *physically*
exclusive instead of exclusive-by-convention.

Two modes, chosen by whether a governed seam is open:

  GOVERNED  (env BS2_SEAM_RUN points at an open seam run-dir — locally, OR
      GB_GOVERNED_HOST + GB_GOVERNED_SEAM_DIR dispatch it via ssh to the exec host
      where the target is reachable)
      Route through the one door — governed_seam.py `exec` -> GovernedExecutor.execute():
      default-deny gate, impact classification, hash-chained audit, scrubbed event stream.
      Fail-CLOSED: if the governed call errors, we return a deny marker; we never silently
      fall back to an ungoverned shell when governance was requested (including when the
      remote dispatch config is incomplete).

  WITNESSED FALLBACK  (no seam — the current live manager/trooper runs)
      Run via the deadlock-safe capture (local, or a short-lived ssh to TROOPER_EXEC_SSH),
      exactly as before — BUT append every command to ONE witnessed audit trail and apply a
      destructive-command guard first, so target contact is never invisible even without a
      full seam. Behaviour is otherwise byte-identical to the old recipes.sh()/run_cmd().
"""
from __future__ import annotations
import contextlib, fcntl, hashlib, ipaddress, json, os, re, shlex, signal, socket, stat, subprocess, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request

CMD_TIMEOUT = int(os.environ.get("RECIPE_CMD_TIMEOUT", "30"))
_GOVERNANCE_CONTEXT = threading.local()


@contextlib.contextmanager
def governance_context(*, run_id="unbound", assessment_id="unbound"):
    previous = getattr(_GOVERNANCE_CONTEXT, "value", None)
    _GOVERNANCE_CONTEXT.value = {
        "run_id": run_id or "unbound",
        "assessment_id": assessment_id or "unbound",
    }
    try:
        yield
    finally:
        if previous is None:
            try:
                del _GOVERNANCE_CONTEXT.value
            except AttributeError:
                pass
        else:
            _GOVERNANCE_CONTEXT.value = previous

# the door rates every command on the seam's own impact axis and passes it as --risk,
# so an unwitnessed (low-ceiling) seam allows read-only recon and denies everything
# else at the governed gate — the risk vocabulary MUST match governed_seam's executor
# (low|medium|high|critical; see battlestation/governed_exec.py _RISK_ORDER).
_IMPACT_RISK = {"read": "low", "mutate": "medium", "destructive": "critical"}
try:
    import impact as _impact_mod
except Exception:
    _impact_mod = None

# ---- destructive-command guard (defense-in-depth; always on, target-independent) ----------
_DESTRUCTIVE = re.compile(
    r"(\brm(?:\s|$)"                                    # deletion is never allowed
    r"|\bunlink(?:\s|$)|\brmdir(?:\s|$)|\bshred(?:\s|$)"
    r"|\bfind\b[^\n]*(?:\s-delete\b|\s-exec\s+rm\b)"
    r"|\b(?:Remove-Item|del|erase)\b"                    # Windows / PowerShell delete
    r"|\bmkfs\b|\bwipefs\b"                             # filesystem wipe
    r"|\bdd\b[^\n]*\bof=/dev/"                          # dd of=/dev/...
    r"|>\s*/dev/sd[a-z]"                                # clobber a raw disk
    r"|\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b"   # host lifecycle
    r"|:\(\)\s*\{\s*:\|:&\s*\}\s*;)",                   # fork bomb
    re.I)


def _blocked(cmd: str):
    m = _DESTRUCTIVE.search(cmd or "")
    return (f"destructive pattern {m.group(1)[:40]!r}" if m else None)


def _runtime_host(value):
    try:
        parsed = urllib.parse.urlsplit(value if "://" in str(value) else f"//{value}")
        return (parsed.hostname or "").rstrip(".").lower()
    except Exception:
        return ""


def _runtime_in_scope(host, selectors):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for selector in selectors:
        selector = str(selector).rstrip(".").lower()
        try:
            network = ipaddress.ip_network(selector, strict=True)
        except ValueError:
            if selector.startswith("*."):
                suffix = selector[1:]
                if host.endswith(suffix) and host != suffix[1:]:
                    return True
            elif host == selector:
                return True
        else:
            if address is not None and address in network:
                return True
    return False


def _runtime_guard(target, *, reserve=True):
    """Reserve one command under the BS2 runtime floor, if configured.

    The policy file is written atomically by Battlestation.  A configured but
    unreadable policy fails closed; absence means this legacy caller did not opt in.
    """
    path = os.environ.get("BS2_GOVERNANCE_POLICY", "").strip()
    if not path:
        return None
    try:
        policy_stat = os.stat(path)
        root_stat = os.stat(os.path.dirname(path))
        if (
            not stat.S_ISREG(policy_stat.st_mode)
            or not stat.S_ISDIR(root_stat.st_mode)
            or policy_stat.st_uid != os.getuid()
            or root_stat.st_uid != os.getuid()
            or policy_stat.st_mode & 0o077
            or root_stat.st_mode & 0o077
        ):
            return "runtime policy permissions are unsafe"
        with open(path, encoding="utf-8") as handle:
            policy = json.load(handle)
    except Exception as exc:
        return f"runtime policy unavailable ({type(exc).__name__})"
    host = _runtime_host(target)
    if not host:
        return "runtime target missing or invalid"
    mode = policy.get("network_mode", "deny")
    if mode == "deny":
        return "runtime network mode denies target contact"
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if mode == "loopback_only" and not loopback:
        return "runtime network mode permits loopback only"
    if mode == "scope_only" and not _runtime_in_scope(host, policy.get("allowed_hosts", [])):
        return "runtime target is outside the configured scope"
    if mode not in {"deny", "loopback_only", "scope_only"}:
        return "runtime network mode is invalid"

    maximum = policy.get("max_actions_per_host", 1)
    window = policy.get("budget_window_seconds", 3600)
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        return "runtime host budget is invalid"
    if isinstance(window, bool) or not isinstance(window, int) or window < 60:
        return "runtime budget window is invalid"
    if not reserve:
        return None
    state_path = os.path.join(os.path.dirname(path), "runtime-actions.jsonl")
    now = int(time.time())
    target_digest = hashlib.sha256(host.encode()).hexdigest()
    try:
        os.makedirs(os.path.dirname(state_path), mode=0o700, exist_ok=True)
        with open(state_path, "a+", encoding="utf-8") as handle:
            os.chmod(state_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            rows = []
            for line in handle:
                try:
                    row = json.loads(line)
                except Exception:
                    return "runtime action ledger is invalid"
                if isinstance(row, dict) and now - int(row.get("at", 0)) < window:
                    rows.append(row)
            used = sum(1 for row in rows if row.get("target_digest") == target_digest)
            if used >= maximum:
                return f"runtime host action budget exhausted ({used}/{maximum})"
            handle.seek(0)
            handle.truncate()
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            handle.write(json.dumps({"at": now, "target_digest": target_digest},
                                    sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:
        return f"runtime action ledger unavailable ({type(exc).__name__})"
    return None


def _command_approval(cmd, target, action_class, timeout, *, estimated_cost_minor=None,
                      currency="USD", run_id=None, assessment_id=None):
    """Block on the local Battlestation human queue before one exact command.

    The broker is mandatory whenever a BS2 runtime policy is configured.  The
    request includes the unmodified command and execution context; server restart,
    timeout, denial, malformed responses, or transport failure all deny execution.
    """
    policy_path = os.environ.get("BS2_GOVERNANCE_POLICY", "").strip()
    if not policy_path:
        return None
    broker = os.environ.get("BS2_GOVERNANCE_BROKER_URL", "").strip()
    token = os.environ.get("BS2_GOVERNANCE_BROKER_TOKEN", "").strip()
    if not broker or not token:
        return "per-command approval broker is unavailable"
    try:
        with open(policy_path, encoding="utf-8") as handle:
            policy = json.load(handle)
        approval_timeout = int(policy.get("command_approval_timeout_seconds", 300))
    except Exception as exc:
        return f"command approval policy unavailable ({type(exc).__name__})"
    body = {
        "command": cmd,
        "target": target or "",
        "action_class": action_class,
        "timeout": int(timeout),
        "run_id": run_id or getattr(_GOVERNANCE_CONTEXT, "value", {}).get(
            "run_id", os.environ.get("BS2_RUN_ID", "unbound")
        ),
        "assessment_id": assessment_id or getattr(_GOVERNANCE_CONTEXT, "value", {}).get(
            "assessment_id", os.environ.get("BS2_ASSESSMENT_ID", "unbound")
        ),
        "currency": currency,
    }
    host = _runtime_host(target)
    resolved_ips = []
    if host:
        try:
            direct = ipaddress.ip_address(host)
        except ValueError:
            try:
                resolved_ips = sorted({
                    row[4][0] for row in socket.getaddrinfo(host, None)
                    if row and row[4] and row[4][0]
                })
            except Exception as exc:
                return f"target DNS resolution failed before approval ({type(exc).__name__})"
        else:
            resolved_ips = [str(direct)]
    body["resolved_ips"] = resolved_ips
    if estimated_cost_minor is not None:
        body["estimated_cost_minor"] = estimated_cost_minor
    request = urllib.request.Request(
        broker,
        data=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
        headers={
            "Content-Type": "application/json",
            "X-BS2-Broker-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=approval_timeout + 10) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
            detail = payload.get("data", {}).get("status") or payload.get("error", {}).get("code")
        except Exception:
            detail = f"http_{exc.code}"
        return f"per-command approval denied ({detail})"
    except Exception as exc:
        return f"per-command approval unavailable ({type(exc).__name__})"
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or data.get("allowed") is not True:
        status = data.get("status", "invalid_response") if isinstance(data, dict) else "invalid_response"
        return f"per-command approval denied ({status})"
    return None


# ---- witnessed audit trail (one append-only line per target command) ----------------------
def _audit(record: dict):
    record["ts"] = int(time.time())
    path = os.environ.get("GB_TARGET_AUDIT", "").strip()
    if not path:
        return
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception:
        pass


# ---- raw capture (operator-authorized diagnostics: full cmd + output) ----------------------
def _raw(cmd, action_class, mode, output):
    path = os.environ.get("GB_RAW_LOG", "").strip()
    if not path:
        return
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps({
                "ts": int(time.time()), "mode": mode, "class": action_class,
                "cmd": cmd, "output": (output or "")[:8000]}, default=str) + "\n")
    except Exception:
        pass


# ---- deadlock-safe capture (the temp-file/own-session pattern shared by both callers) ------
def _capture(argv, timeout):
    """Run argv; return combined stdout+stderr. A backgrounded child (nc -lvnp &, chisel)
    inherits the stdout pipe, so a plain capture_output read never sees EOF and wedges the
    engine forever. Route output to a temp FILE, detach into its own session, kill the whole
    process group on timeout."""
    try:
        with tempfile.TemporaryFile(mode="w+", errors="replace") as tf:
            p = subprocess.Popen(argv, stdout=tf, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, text=True, start_new_session=True)
            try:
                p.wait(timeout=timeout)
                tf.seek(0); return tf.read()
            except subprocess.TimeoutExpired:
                try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception: pass
                try: p.wait(timeout=5)
                except Exception: pass
                tf.seek(0); return tf.read() + "\n(timeout)"
    except Exception as e:
        return f"(error: {e})"


def _governed_target():
    """Resolve the governed route: {'mode': 'off'} = no seam (witnessed fallback);
    'local' = seam on THIS host; 'remote' = dispatch via ssh to the exec host
    (GB_GOVERNED_HOST) where tun0/HTB reachability lives; 'refused' = config incomplete
    (fail-closed, never guessed, never falls back to an ungoverned shell)."""
    host = os.environ.get("GB_GOVERNED_HOST", "").strip()
    if host:
        seam = (os.environ.get("GB_GOVERNED_SEAM_DIR", "").strip()
                or os.environ.get("BS2_SEAM_RUN", "").strip())
        if not seam:
            return {"mode": "refused",
                    "msg": (f"[GOVERNED CONFIG (fail-closed, not run): GB_GOVERNED_HOST={host} "
                            f"set but GB_GOVERNED_SEAM_DIR missing]")}
        seam_py = (os.environ.get("GB_GOVERNED_SEAM_PY", "").strip()
                   or "~/gunbelt/live/governed_seam.py")
        return {"mode": "remote", "host": host, "seam": seam, "seam_py": seam_py}
    seam = os.environ.get("BS2_SEAM_RUN", "").strip()
    if seam and os.path.isdir(seam):
        return {"mode": "local", "seam": seam}
    return {"mode": "off"}


def _run_governed(cmd, action_class, timeout):
    """Route one command through the governed door — locally, or dispatched via ssh to
    the exec host. Returns None when no seam is open (caller uses the witnessed
    fallback); fail-closed on error, on deny, and on incomplete config."""
    gt = _governed_target()
    if gt["mode"] == "off":
        return None
    if gt["mode"] == "refused":
        _audit({"mode": "governed", "class": action_class, "cmd_sha": _sha(cmd),
                "result": "refused", "detail": gt["msg"][:200]})
        return gt["msg"]
    risk = "low"
    if _impact_mod is not None:
        try:
            risk = _IMPACT_RISK.get(_impact_mod.classify(cmd), "low")
        except Exception:
            pass
    # The seam's contract is argv TOKENS (each preserved as one shell word) — a raw
    # command blob would arrive quoted into one word and fail as 'no such file'.
    # Wrap as `bash -lc <cmd>`: the seam quotes the three words faithfully and bash
    # restores full shell semantics (&&, |, redirection) for the command string.
    if gt["mode"] == "local":
        seam_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "governed_seam.py")
        argv = ["python3", seam_py, "exec", "--run-dir", gt["seam"],
                "--class", action_class, "--risk", risk, "--", "bash", "-lc", cmd]
        label = "local"
    else:
        remote = ["python3", gt["seam_py"], "exec", "--run-dir", gt["seam"],
                  "--class", action_class, "--risk", risk, "--", "bash", "-lc", cmd]
        argv = ["ssh", "-o", "ControlPath=none", "-o", "ConnectTimeout=8",
                "-o", "BatchMode=yes", gt["host"], shlex.join(remote)]
        label = f"remote:{gt['host']}"
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 15)
    except Exception as e:
        _audit({"mode": "governed", "class": action_class, "host": label,
                "cmd_sha": _sha(cmd), "result": "error", "detail": str(e)[:200]})
        return f"[GOVERNED ERROR (fail-closed, not run): {e}]"
    if p.returncode == 0:
        _audit({"mode": "governed", "class": action_class, "host": label,
                "cmd_sha": _sha(cmd), "result": "allowed"})
        return p.stdout
    _audit({"mode": "governed", "class": action_class, "host": label,
            "cmd_sha": _sha(cmd), "result": "denied", "detail": (p.stderr or "")[-200:]})
    return f"[GOVERNED DENY: {(p.stderr or '').strip()[-160:]}]"


def _sha(cmd):
    import hashlib
    return hashlib.sha256((cmd or "").encode()).hexdigest()[:16]


def classify_action(cmd):
    """Capability/scope classification (canonical BS2-evaluate step, lightweight form):
    routine discovery commands are recon-class (always charter-sanctioned); anything
    attack-shaped is exploit-class (needs a witnessed capability in governed mode)."""
    low = (cmd or "").lower()
    if re.search(r"\b(?:nmap|masscan|rustscan|gobuster|feroxbuster|ffuf|dirb|dirsearch|"
                 r"whatweb|wappalyzer|wpscan|nikto|curl|wget|dig|nslookup|dnsrecon|"
                 r"smbclient|enum4linux\S*|rpcclient|rpcinfo|showmount|nfs-ls|snmpwalk|"
                 r"onesixtyone|ldapsearch|smtp-user-enum|nc\s+-z|ncat\s+-z)\b", low):
        return "web.recon"
    if re.search(r"\bsearchsploit\b|\bnuclei\b.*-tags", low):
        return "web.recon"   # catalog lookups are research, not target contact
    return "web.exploit"


_HITL_ENV = ("BS2_GOVERNANCE_POLICY", "BS2_GOVERNANCE_BROKER_URL", "BS2_GOVERNANCE_BROKER_TOKEN")


def _require_hitl_gate():
    """When BS2_REQUIRE_HITL is truthy, turn 'HITL is configured' into 'HITL cannot be
    skipped': refuse to run unless the FULL per-command approval path is wired — a
    governance policy AND a broker URL AND a broker token. Without this, forgetting to
    set the policy makes `_command_approval` return None (no gate) and the witnessed
    fallback runs UNGOVERNED. This gate fails closed for operators who want HITL always.
    """
    val = os.environ.get("BS2_REQUIRE_HITL", "").strip().lower()
    if val in ("", "0", "false", "no", "off"):
        return None
    missing = [name for name in _HITL_ENV if not os.environ.get(name, "").strip()]
    if missing:
        return ("BS2_REQUIRE_HITL is set but per-command approval is not wired "
                f"(missing: {', '.join(missing)}) — refusing to run ungoverned")
    return None


def run(cmd, target=None, *, action_class="web.exploit", timeout=None, ssh_host=None,
        estimated_cost_minor=None, currency="USD", run_id=None, assessment_id=None):
    """THE single target-contact primitive. Returns combined stdout+stderr (str).

    - If BS2_REQUIRE_HITL is set, refuses unless per-command approval is fully wired.
    - Applies the destructive-command guard.
    - If a governed seam is open (BS2_SEAM_RUN), routes through the governed door (fail-closed).
    - Otherwise runs the witnessed fallback: local, or a short-lived ssh to ssh_host
      (defaults to TROOPER_EXEC_SSH), with the command appended to the audit trail.
    """
    timeout = CMD_TIMEOUT if timeout is None else timeout
    hitl_bad = _require_hitl_gate()
    if hitl_bad:
        _audit({"mode": "require-hitl", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": hitl_bad})
        return f"[target-exec BLOCKED: {hitl_bad}]"
    bad = _blocked(cmd)
    if bad:
        _audit({"mode": "guard", "cmd_sha": _sha(cmd), "result": "blocked", "detail": bad})
        return f"[target-exec BLOCKED: {bad}]"
    runtime_bad = _runtime_guard(target, reserve=False)
    if runtime_bad:
        _audit({"mode": "runtime-guard", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": runtime_bad})
        return f"[target-exec BLOCKED: {runtime_bad}]"
    approval_bad = _command_approval(
        cmd, target, action_class, timeout,
        estimated_cost_minor=estimated_cost_minor, currency=currency,
        run_id=run_id, assessment_id=assessment_id,
    )
    if approval_bad:
        _audit({"mode": "command-approval", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": approval_bad})
        return f"[target-exec BLOCKED: {approval_bad}]"
    runtime_bad = _runtime_guard(target, reserve=True)
    if runtime_bad:
        _audit({"mode": "runtime-guard", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": runtime_bad})
        return f"[target-exec BLOCKED: {runtime_bad}]"

    # governed door — local seam, or ssh-dispatch to the exec host (GB_GOVERNED_HOST)
    # where tun0/HTB reachability lives. Fail-closed: a refusal/config error returns the
    # marker, never the witnessed fallback.
    out = _run_governed(cmd, action_class, timeout)
    if out is not None:
        _raw(cmd, action_class, "governed", out)
        return out

    # witnessed fallback — behaviourally identical to the old recipes.sh()/run_cmd()
    host = (ssh_host if ssh_host is not None
            else os.environ.get("TROOPER_EXEC_SSH", "").strip())
    if host:
        argv = ["ssh", "-o", "ControlPath=none", "-o", "ConnectTimeout=8",
                "-o", "BatchMode=yes", host, "bash -lc " + shlex.quote(cmd)]
    else:
        argv = ["bash", "-lc", cmd]
    _audit({"mode": "ungoverned", "class": action_class, "host": host or "local",
            "cmd_sha": _sha(cmd), "result": "ran"})
    out = _capture(argv, timeout)
    _raw(cmd, action_class, "ungoverned", out)
    return out


__all__ = ["run", "governance_context", "CMD_TIMEOUT"]
