#!/usr/bin/env python3
"""Honest declarative roster: routing metadata only, never executable tactics."""
from __future__ import annotations

from chain_manager import PRIMITIVES

REQUIRED_KEYS = frozenset({"name", "signals", "primitive", "requires", "adapters"})
REQUIREMENTS = frozenset({"endpoint", "object", "workflow", "identity",
                          "response-delta", "browser", "component"})
ADAPTERS = frozenset({"nuclei", "katana", "mitmproxy", "playwright", "zap", "restler",
                      "schemathesis", "interactsh", "burp"})


def _entry(name, signals, primitive=None, requires=(), adapters=()):
    return {"name": name, "signals": list(signals), "primitive": primitive,
            "requires": list(requires), "adapters": list(adapters)}


# Only direct joins into chain_manager's closed primitive vocabulary are active.
TROOPERS = [
    _entry("upload", ("upload", "multipart/form-data"), "file-upload",
           ("endpoint",), ("mitmproxy", "playwright")),
    _entry("ssrf", ("url=", "webhook", "fetch"), "ssrf",
           ("endpoint",), ("mitmproxy", "interactsh")),
    _entry("data-exposure", (".git", ".env", "api key in js"), "cred-disclosure",
           ("endpoint",), ("katana", "nuclei")),
    _entry("open-redirect", ("redirect=", "returnurl", "next="), "open-redirect",
           ("endpoint", "browser"), ("playwright", "zap")),
    _entry("oauth", ("/authorize", "openid", "callback"), "oauth-callback",
           ("endpoint", "identity", "browser"), ("mitmproxy", "playwright")),
    _entry("cache-poison", ("x-cache", "vary", "cdn cache"), "cache-poisoning",
           ("endpoint", "response-delta"), ("mitmproxy", "playwright")),
    _entry("proto-pollution", ("__proto__", "constructor", "deep merge"),
           "prototype-pollution", ("endpoint",), ("mitmproxy", "schemathesis")),
    _entry("host-header", ("x-forwarded-host", "host header"), "host-header-trust",
           ("endpoint",), ("mitmproxy", "zap")),
]


_UNMAPPED = {
    "sqli": ("sql", "database error"),
    "nosqli": ("mongo", "nosql"),
    "cmdi": ("exec", "system(", "cmd="),
    "ssti": ("{{", "jinja", "template"),
    "xss-server": ("reflected", "stored xss"),
    "xss-dom": ("location.hash", "document.write"),
    "xxe": ("<?xml", "soap", "svg upload"),
    "deserial": ("java serialized", "pickle", "viewstate"),
    "lfi": ("../", "file=", "include"),
    "authn": ("login", "session", "password reset"),
    "bola": ("id=", "user_id", "sequential id"),
    "jwt": ("bearer", "jwt", "jwks"),
    "component-cve": ("version", "server:", "banner"),
    "crypto": ("ecb", "static iv", "weak tls"),
    "misconfig": ("directory listing", "debug", "phpinfo"),
    "csrf": ("no csrf token", "samesite"),
    "bizlogic": ("checkout", "workflow", "step skip"),
    "bopla": ("role", "is_admin", "extra fields"),
    "bfla": ("/admin/api", "method override"),
    "race": ("redeem", "idempotency", "quota"),
    "desync": ("transfer-encoding", "content-length dup"),
    "supply-chain": ("lockfile", "sbom", "unsigned"),
    "cloud-iam": ("metadata", "iam", "service account"),
    "resource-amp": ("graphql nesting", "no rate limit"),
    "origin-boundary": ("cors", "postmessage", "iframe"),
    "ai-agent": ("prompt", "vector", "tool call"),
    "api-trust": ("webhook", "signature header", "integration"),
    "subdomain-takeover": ("cname", "unclaimed", "dangling dns"),
    "api-inventory": ("swagger", "openapi", "/v2"),
    "fail-open": ("timeout", "partial commit", "dependency down"),
    "ad-privesc": ("ldap", "kerberos", "bloodhound"),
    "adcs": ("certsrv", "certificate template", "esc"),
    "linux-privesc": ("suid", "sudo -l", "gtfobins"),
}

DEAD_WEIGHT = [
    {**_entry(name, signals),
     "reason": "no direct mapping into chain_manager.PRIMITIVES; manager reasoning required"}
    for name, signals in _UNMAPPED.items()
]


def validate():
    """Return structural errors; an empty list means the full 41-entry registry is valid."""
    problems = []
    rows = TROOPERS + DEAD_WEIGHT
    if len(rows) != 41:
        problems.append(f"expected 41 roster entries, got {len(rows)}")
    names = [row.get("name") for row in rows]
    if len(set(names)) != len(names):
        problems.append("trooper names must be unique")
    for row in rows:
        missing = REQUIRED_KEYS - set(row)
        if missing:
            problems.append(f"{row.get('name')}: missing {sorted(missing)}")
        if not isinstance(row.get("signals"), list) or not row.get("signals"):
            problems.append(f"{row.get('name')}: signals must be a non-empty list")
        if not set(row.get("requires", ())) <= REQUIREMENTS:
            problems.append(f"{row.get('name')}: unknown requirement")
        if not set(row.get("adapters", ())) <= ADAPTERS:
            problems.append(f"{row.get('name')}: unknown adapter")
        primitive = row.get("primitive")
        if row in TROOPERS and primitive not in PRIMITIVES:
            problems.append(f"{row.get('name')}: unmapped primitive {primitive!r}")
        if row in DEAD_WEIGHT and (primitive is not None or not row.get("reason")):
            problems.append(f"{row.get('name')}: dead weight needs no primitive and a reason")
    return problems


__all__ = ["TROOPERS", "DEAD_WEIGHT", "validate", "REQUIRED_KEYS", "REQUIREMENTS",
           "ADAPTERS"]
