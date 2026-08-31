#!/usr/bin/env python3
"""chain_manager — cross-specialist composition (BS2 doc §7).

Two individually medium-confidence observations can compose into a serious route.
Specialists publish PRIMITIVES into the shared graph (typed signals with loci); this
module recognizes the composition pairs and raises a CHAIN candidate with the
combined impact — the manager decides whether to pursue it.

Pairs (from the doc, generalized — no target-specific code):
  open-redirect      + oauth_callback       -> token theft via redirect chain
  ssrf               + metadata_exposure    -> cloud metadata exfil
  stored_xss         + privileged_review    -> privilege escalation via review flow
  file_upload        + async_parser         -> parser-triggered execution
  host_header_trust  + password_recovery    -> account takeover via poisoned reset
  cache_poisoning    + authenticated_content-> poisoned cache for privileged pages
  prototype_pollution+ security_gadget      -> polluted prototype reaches a gadget
  cred_disclosure    + tenant_boundary_fail -> cross-tenant credential compromise
"""
from __future__ import annotations

COMPOSITIONS = [
    {"pair": ("open-redirect", "oauth-callback"), "chain": "oauth-token-theft",
     "impact": "critical"},
    {"pair": ("ssrf", "metadata-exposure"), "chain": "cloud-metadata-exfil",
     "impact": "high"},
    {"pair": ("stored-xss", "privileged-review"), "chain": "xss-to-privesc",
     "impact": "high"},
    {"pair": ("file-upload", "async-parser"), "chain": "upload-to-execution",
     "impact": "critical"},
    {"pair": ("host-header-trust", "password-recovery"), "chain": "reset-poisoning-ato",
     "impact": "critical"},
    {"pair": ("cache-poisoning", "authenticated-content"), "chain": "poisoned-priv-cache",
     "impact": "medium"},
    {"pair": ("prototype-pollution", "security-gadget"), "chain": "proto-pollution-rce",
     "impact": "critical"},
    {"pair": ("cred-disclosure", "tenant-boundary-fail"), "chain": "cross-tenant-cred",
     "impact": "critical"},
]

# free-form signal text -> canonical primitive key (closed vocabulary, best-effort)
_ALIASES = {
    "open-redirect": (r"open\s*redirect|redirect\s*to",),
    "oauth-callback": (r"oauth|oidc|callback",),
    "ssrf": (r"\bssrf\b|server.side.request",),
    "metadata-exposure": (r"metadata|169\.254\.169\.254",),
    "stored-xss": (r"stored\s*xss|\bxss\b",),
    "privileged-review": (r"admin\s*review|moderation|approval\s*flow",),
    "file-upload": (r"file\s*upload|upload\s*endpoint",),
    "async-parser": (r"document\s*parser|pdf|conversion\s*queue|async\s*process",),
    "host-header-trust": (r"host\s*header",),
    "password-recovery": (r"password\s*reset|recovery|forgot",),
    "cache-poisoning": (r"cache\s*poison|web.cache",),
    "authenticated-content": (r"authenticated\s*content|profile\s*page",),
    "prototype-pollution": (r"prototype\s*pollution|__proto__",),
    "security-gadget": (r"gadget|template\s*engine|deserializ",),
    "cred-disclosure": (r"credential\s*disclos|password\s*exposure|secret\s*leak",),
    "tenant-boundary-fail": (r"tenant\s*boundary|cross.tenant|isolation\s*fail",),
}
PRIMITIVES = frozenset(_ALIASES)


def primitive_of(signal_text):
    """Map one observation string to a canonical primitive key (or None). Content-blind
    closed vocabulary: unrecognized prose maps to nothing, never to a guess."""
    import re
    low = str(signal_text or "").lower()
    for key, pats in _ALIASES.items():
        if any(re.search(p, low) for p in pats):
            return key
    return None


def recognize(signals):
    """Given typed observation strings (e.g. 'signal:open-redirect:http_80'), return the
    chain candidates whose BOTH primitives appear. Two medium-confidence observations ->
    one composed serious route."""
    prims = set()
    for s in signals or []:
        k = primitive_of(s)
        if k:
            prims.add(k)
        elif str(s).startswith("signal:"):
            prims.add(str(s).split(":", 2)[1] if ":" in str(s)[7:] else str(s)[7:])
    found = []
    for comp in COMPOSITIONS:
        if set(comp["pair"]) <= prims:
            found.append({"chain": comp["chain"], "impact": comp["impact"],
                          "from": sorted(comp["pair"])})
    return found


__all__ = ["COMPOSITIONS", "PRIMITIVES", "primitive_of", "recognize"]
