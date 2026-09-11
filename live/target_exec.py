#!/usr/bin/env python3
"""Single supported target-contact door for BS2 0.2.
Mandatory scope + exact approval + budget + durable intent + pinned HTTP transport.
No shell, SSH, optional-seam or witnessed fallback. Arbitrary network tools require
a future audited sandbox backend. Historical helper names fail closed.
"""
from __future__ import annotations
import contextlib, fcntl, hashlib, ipaddress, json, os, re, shlex, signal, socket, stat, subprocess, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request
import sys
from pathlib import Path
# Direct scripts (live/autocannon.py etc.) also need the packaged runtime.
_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from bs2.journal import digest, Journal
from bs2.memory import BattleMemory
from bs2 import transport

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
        return "runtime policy is required"
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
                      currency="USD", run_id=None, assessment_id=None, binding=None):
    """Block on the local Battlestation human queue before one exact command.

    The broker is mandatory whenever a BS2 runtime policy is configured.  The
    request includes the unmodified command and execution context; server restart,
    timeout, denial, malformed responses, or transport failure all deny execution.
    """
    policy_path = os.environ.get("BS2_GOVERNANCE_POLICY", "").strip()
    if not policy_path:
        return "runtime policy is required"
    broker = os.environ.get("BS2_GOVERNANCE_BROKER_URL", "").strip()
    token = os.environ.get("BS2_GOVERNANCE_BROKER_TOKEN", "").strip()
    if not broker or not token:
        return "per-command approval broker is unavailable"
    try:
        with open(policy_path, encoding="utf-8") as handle:
            policy = json.load(handle)
        approval_timeout = min(600, max(1, int(policy.get("command_approval_timeout_seconds", 300))))
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
    if not binding:
        return "exact execution binding missing"
    body.update(binding)
    body["nonce"] = os.urandom(16).hex()
    body["expires_at"] = time.time() + approval_timeout
    body["request_digest"] = digest(body)
    parsed_broker = urllib.parse.urlsplit(broker)
    if parsed_broker.scheme != "http" or parsed_broker.hostname not in ("127.0.0.1", "::1") or parsed_broker.username:
        return "approval broker must be a numeric loopback HTTP endpoint"
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
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
        with opener.open(request, timeout=approval_timeout + 10) as response:
            payload = json.loads(response.read(65537))
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
    if (data.get("request_digest") != body["request_digest"] or data.get("nonce") != body["nonce"]
            or data.get("expires_at") != body["expires_at"] or time.time() >= body["expires_at"]):
        return "approval binding mismatch or expired"
    _GOVERNANCE_CONTEXT.approval = {k: data[k] for k in ("request_digest", "nonce", "expires_at", "id")}
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
    raise RuntimeError("uncontained capture removed; use the supported target door")


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
    if seam:
        return {"mode": "refused", "msg": "[GOVERNED CONFIG (fail-closed, not run): configured seam directory is missing]"}
    return {"mode": "off"}


def _run_governed(cmd, action_class, timeout):
    return "[target-exec BLOCKED: legacy seam execution has no supported containment contract]"


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
    missing = [name for name in _HITL_ENV if not os.environ.get(name, "").strip()]
    if missing:
        return ("BS2_REQUIRE_HITL is set but per-command approval is not wired "
                f"(missing: {', '.join(missing)}) — refusing to run ungoverned")
    return None


def _denylist_extra_block(cmd):
    """Add-only operator denylist from the governance policy's `denylist_extra` — the Rules-of-
    Engagement wizard (scripts/bs2-roe) writes these ("things that must be impossible this
    engagement"). This ONLY extends the hardcoded destructive floor, never shrinks it. A pattern
    that is not valid regex is matched literally, so a plain string the operator typed always
    blocks. Unreadable/absent policy => no extra denials here (the runtime guard fail-closes
    on an unreadable policy separately)."""
    path = os.environ.get("BS2_GOVERNANCE_POLICY", "").strip()
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            patterns = json.load(fh).get("denylist_extra", []) or []
    except Exception:
        return None
    for pat in patterns:
        if not isinstance(pat, str) or not pat.strip():
            continue
        try:
            hit = re.search(pat, cmd or "", re.I)
        except re.error:
            hit = pat.lower() in (cmd or "").lower()
        if hit:
            return f"RoE denylist ({pat[:60]})"
    return None


def run(cmd, target=None, *, action_class="web.exploit", timeout=None, ssh_host=None,
        estimated_cost_minor=None, currency="USD", run_id=None, assessment_id=None):
    """Exact reviewed HTTP request -> normalized output and durable structured receipt.
    Scope, approval and journal are mandatory. Unsupported transports refuse.
    """
    timeout = CMD_TIMEOUT if timeout is None else timeout
    _GOVERNANCE_CONTEXT.approval = None
    _GOVERNANCE_CONTEXT.last_receipt = None
    if not os.environ.get("BS2_GOVERNANCE_POLICY"):
        return f"[target-exec BLOCKED: {_require_hitl_gate()}]"
    roe_bad = _denylist_extra_block(cmd)
    if roe_bad:
        _audit({"mode": "roe-denylist", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": roe_bad})
        return f"[target-exec BLOCKED: {roe_bad}]"
    bad = _blocked(cmd)
    if bad:
        _audit({"mode": "guard", "cmd_sha": _sha(cmd), "result": "blocked", "detail": bad})
        return f"[target-exec BLOCKED: {bad}]"
    runtime_bad = _runtime_guard(target, reserve=False)
    if runtime_bad:
        _audit({"mode": "runtime-guard", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": runtime_bad})
        return f"[target-exec BLOCKED: {runtime_bad}]"
    hitl_bad = _require_hitl_gate()
    if hitl_bad:
        return f"[target-exec BLOCKED: {hitl_bad}]"
    if ssh_host or os.environ.get("TROOPER_EXEC_SSH") or os.environ.get("GB_GOVERNED_HOST") or os.environ.get("BS2_SEAM_RUN"):
        return "[target-exec BLOCKED: legacy SSH/seam backend has no supported containment contract; no fallback]"
    directory = os.environ.get("BS2_RUN_DIR", "")
    if not directory:
        return "[target-exec BLOCKED: BS2_RUN_DIR is required for durable receipts and Cairn]"
    try:
        policy_bytes = Path(os.environ["BS2_GOVERNANCE_POLICY"]).read_bytes()
        policy = json.loads(policy_bytes)
        plan = transport.prepare(cmd, target, policy, float(timeout))
        if plan["method"] not in ("GET", "HEAD", "OPTIONS") and action_class in ("web.recon", "net.recon"):
            action_class = "web.exploit"
        memory = BattleMemory(directory)
        conditions = {"principal": os.environ.get("BS2_PRINCIPAL_ID", "anonymous"),
                      "session_epoch": os.environ.get("BS2_SESSION_EPOCH", "unknown"),
                      "target_generation": os.environ.get("BS2_TARGET_GENERATION", "unknown")}
        binding = {"execution": plan, "policy_digest": hashlib.sha256(policy_bytes).hexdigest(),
                   "conditions": conditions, "battle": memory.entity, "resolved_ips": plan["resolved_ips"]}
    except Exception as exc:
        return f"[target-exec BLOCKED: {exc}]"
    approval_bad = _command_approval(
        cmd, target, action_class, timeout,
        estimated_cost_minor=estimated_cost_minor, currency=currency,
        run_id=run_id, assessment_id=assessment_id, binding=binding,
    )
    if approval_bad:
        _audit({"mode": "command-approval", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": approval_bad})
        return f"[target-exec BLOCKED: {approval_bad}]"
    try:
        if hashlib.sha256(Path(os.environ["BS2_GOVERNANCE_POLICY"]).read_bytes()).hexdigest() != binding["policy_digest"]:
            return "[target-exec BLOCKED: policy changed after approval]"
    except OSError:
        return "[target-exec BLOCKED: policy disappeared after approval]"
    approval = getattr(_GOVERNANCE_CONTEXT, "approval", None)
    if not approval or time.time() >= approval["expires_at"]:
        return "[target-exec BLOCKED: missing or expired exact approval receipt]"
    runtime_bad = _runtime_guard(target, reserve=True)
    if runtime_bad:
        _audit({"mode": "runtime-guard", "cmd_sha": _sha(cmd), "result": "blocked",
                "detail": runtime_bad})
        return f"[target-exec BLOCKED: {runtime_bad}]"

    try:
        # Durable intent precedes contact. An unmatched intent after a crash means
        # unknown outcome, NEVER a negative or an automatic retry permission.
        intent = memory.journal.append("intent", {"approval": approval, "backend": plan["backend"],
                                      "conditions": conditions, "command_sha256": hashlib.sha256(cmd.encode()).hexdigest()})
        if time.time() >= approval["expires_at"]:
            return "[target-exec BLOCKED: approval expired before dispatch]"
        out, result = transport.execute(plan)
        result.update(conditions)
        result.update({"approval_digest": approval["request_digest"], "intent_seq": intent["seq"],
                       "backend": plan["backend"]})
        receipt = memory.journal.append("observation", result)
        _GOVERNANCE_CONTEXT.last_receipt = receipt
        memory.fold().close()
        _raw(cmd, action_class, plan["backend"], out)
        return out
    except Exception as exc:
        try:
            memory.journal.append("inconclusive", {"reason": type(exc).__name__, "conditions": conditions,
                                                   "approval_digest": approval["request_digest"]})
            memory.fold().close()
        except Exception:
            pass
        return f"[target-exec INCONCLUSIVE: {type(exc).__name__}; do not interpret as a negative result]"


__all__ = ["run", "governance_context", "CMD_TIMEOUT"]
