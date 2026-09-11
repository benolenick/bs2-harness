"""Contained HTTP capability: no shell, proxies, redirects, or second DNS lookup.

This is application-level destination containment, NOT an OS sandbox. Arbitrary
network tools require a separately implemented sandbox backend and are refused.
"""
import hashlib
import http.client
import ipaddress
import json
import shlex
import socket
import ssl
import time
import threading
from urllib.parse import urlsplit
from .journal import digest

MAX_RESPONSE = 1024 * 1024


def prepare(command, target, policy, timeout):
    words = shlex.split(command)
    if not words or words.pop(0) != "curl":
        raise ValueError("containment unavailable for arbitrary shell/tool commands; supported backend: pinned HTTP curl subset")
    method, headers, body, url, insecure = "GET", {}, None, None, False
    explicit_method = False
    i = 0
    while i < len(words):
        word = words[i]
        if word in ("-s", "-S", "-i", "--silent", "--show-error", "--include"):
            pass
        elif word.startswith("-") and not word.startswith("--") and set(word[1:]) <= set("sSik"):
            insecure |= "k" in word
        elif word in ("-k", "--insecure"):
            insecure = True
        elif word in ("-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--max-time", "-m", "-w", "--write-out", "-b", "--cookie"):
            i += 1
            if i >= len(words):
                raise ValueError("missing curl option value")
            value = words[i]
            if word in ("-X", "--request"):
                method = value.upper()
                explicit_method = True
            elif word in ("-H", "--header"):
                name, sep, val = value.partition(":")
                if not sep or not name.strip() or any(c in value for c in "\r\n"):
                    raise ValueError("invalid header")
                name = name.strip().lower()
                if name in ("host", "connection", "content-length", "transfer-encoding", "upgrade", "proxy-authorization", "proxy-connection", "trailer"):
                    raise ValueError("routing/framing headers are not supported")
                if name in headers:
                    raise ValueError("duplicate header")
                headers[name] = val.strip()
            elif word in ("-d", "--data", "--data-raw", "--data-binary"):
                if value.startswith("@") or body is not None:
                    raise ValueError("file uploads and repeated bodies are not supported")
                body = value
                if not explicit_method:
                    method = "POST"
            elif word in ("-b", "--cookie"):
                # File reads could leak local credentials to a target. Callers must
                # materialize a scope-checked session explicitly as a Cookie header.
                raise ValueError("cookie files are unsupported; use an explicit scoped Cookie header")
            elif word in ("--max-time", "-m"):
                timeout = min(float(value), timeout)
            else:
                if value not in (r"\n__GB_STATUS__:%{http_code} __GB_TIME__:%{time_total}", "%{http_code}"):
                    raise ValueError("unsupported curl output template")
        elif word.startswith("-"):
            raise ValueError(f"unsupported curl option: {word}")
        elif url is None:
            url = word
        else:
            raise ValueError("exactly one URL is allowed; shell syntax is not supported")
        i += 1
    parsed = urlsplit(url or "")
    scoped = urlsplit(str(target) if "://" in str(target) else "//" + str(target))
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("invalid HTTP URL")
    if parsed.hostname.rstrip(".").lower() != (scoped.hostname or "").rstrip(".").lower():
        raise ValueError("command destination differs from approved target")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if scoped.scheme and (scoped.scheme != parsed.scheme or (scoped.port or (443 if scoped.scheme == "https" else 80)) != port):
        raise ValueError("command origin differs from approved target")
    if port not in policy.get("allowed_ports", []):
        raise ValueError("destination port is outside policy.allowed_ports (explicit ports required)")
    if method not in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"):
        raise ValueError("unsupported HTTP method")
    if insecure and not policy.get("allow_insecure_tls", False):
        raise ValueError("insecure TLS requires explicit policy.allow_insecure_tls")
    if not 0 < timeout <= 120:
        raise ValueError("timeout must be between 0 and 120 seconds")
    addresses = sorted({row[4][0] for row in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError("no target addresses")
    mode = policy.get("network_mode")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_multicast or ip.is_unspecified or (mode == "loopback_only" and not ip.is_loopback):
            raise ValueError("resolved address is forbidden by network policy")
        # Hostname selectors authorize that hostname's pinned DNS result; optional
        # CIDRs additionally constrain it (e.g. prohibit DNS resolving onto a LAN).
        networks = policy.get("allowed_destination_cidrs")
        if networks and not any(ip in ipaddress.ip_network(n, strict=True) for n in networks):
            raise ValueError("resolved address is outside destination CIDRs")
    return {"backend": "pinned-http-v1", "url": url, "host": parsed.hostname,
            "port": port, "scheme": parsed.scheme, "path": (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
            "method": method, "headers": headers, "body": body, "insecure": insecure,
            "timeout": timeout, "resolved_ips": addresses}


def execute(plan):
    """One connection to one already-approved numeric destination; no redirect follow."""
    started = time.monotonic()
    address = plan["resolved_ips"][0]
    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    conn = http.client.HTTPConnection(plan["host"], plan["port"], timeout=plan["timeout"])
    def expire():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    deadline = threading.Timer(plan["timeout"], expire)
    deadline.daemon = True
    deadline.start()
    try:
        sock.settimeout(plan["timeout"])
        sock.connect((address, plan["port"]))
        if plan["scheme"] == "https":
            ctx = ssl._create_unverified_context() if plan["insecure"] else ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=plan["host"])
        conn.sock = sock
        data = plan["body"].encode() if plan["body"] is not None else None
        conn.request(plan["method"], plan["path"], body=data, headers=plan["headers"])
        response = conn.getresponse()
        chunks, total = [], 0
        # Bound both total wall time and bytes, including slow-drip responses.
        while True:
            if response.isclosed():
                break
            remaining = plan["timeout"] - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("response deadline exceeded")
            sock.settimeout(remaining)
            chunk = response.read1(min(65536, MAX_RESPONSE + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RESPONSE:
                raise ValueError("response exceeds 1 MiB limit")
        body = b"".join(chunks)
        elapsed = time.monotonic() - started
        text = body.decode("utf-8", errors="replace")
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            obj = {}
        if not isinstance(obj, dict):
            obj = {}
        identity = {k: str(obj[k])[:100] for k in ("id", "owner_id", "principal_id") if isinstance(obj.get(k), (str, int))}
        result = {"status": response.status, "body_sha256": hashlib.sha256(body).hexdigest(),
                  "endpoint": f"{plan['scheme']}://{plan['host']}:{plan['port']}" + urlsplit(plan["url"]).path,
                  "body_bytes": len(body), "identity": identity,
                  "method": plan["method"], "request_key": digest({k: plan[k] for k in ("url", "method", "body")}),
                  "credential_fingerprint": digest({k: v for k, v in plan["headers"].items() if k in ("authorization", "cookie")}),
                  "destination": address, "port": plan["port"], "elapsed_seconds": round(elapsed, 4)}
        # Legacy adapters consume this normalized representation, but proof logic
        # consumes the structured receipt above, never strings from target content.
        output = f"HTTP/1.1 {response.status} {response.reason}\n"
        output += "\n".join(f"{k}: {v}" for k, v in response.getheaders()) + "\n\n" + text
        output += f"\n__GB_STATUS__:{response.status} __GB_TIME__:{elapsed:.6f}"
        return output, result
    finally:
        deadline.cancel()
        conn.close()
        sock.close()
