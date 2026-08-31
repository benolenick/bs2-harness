#!/usr/bin/env python3
"""memoria_enrich — fold Memoria (pentest RAG on your-host :8009) technique hints into expert briefs.

Memoria's job in the new spine is ADVISOR, not lane: when a specialist is about to attack a
class/endpoint, arm its prompt with the most relevant known techniques from the corpus
(SecLists/HackTricks/ATT&CK/PayloadsAllTheThings). Reuses memoria_assist._query (ssh your-host ->
curl :8009/search). FAILS SOFT — any error/timeout returns "" and never blocks dispatch.

  hints_for(cls, items, target, k, timeout) -> str   # a "## Memoria hints" markdown block, or ""
"""
from __future__ import annotations
import os, re, sys

# reuse the proven ssh+curl plumbing
_MA_DIR = "/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria"
sys.path.insert(0, _MA_DIR)
try:
    from memoria_assist import _query as _memoria_query, _clean as _memoria_clean  # type: ignore
except Exception:
    _memoria_query = None
    def _memoria_clean(t): return re.sub(r"\s+", " ", (t or "")).strip()

# class -> a corpus query seed (technique-focused, web-app framed)
_SEED = {
    "sqli": "SQL injection UNION error-based blind boolean sqlite login bypass web API exploitation",
    "nosqli": "NoSQL injection MongoDB operator injection $ne $gt $regex authentication bypass",
    "broken-access-control": "broken access control IDOR insecure direct object reference forced browsing authorization bypass REST API",
    "auth-bypass": "JWT attack alg none weak secret forgery authentication bypass password reset web app",
    "path-traversal": "path traversal directory traversal LFI arbitrary file read null byte extension filter bypass",
    "xss": "cross site scripting stored reflected DOM XSS payloads filter bypass",
    "llm-injection": "prompt injection LLM jailbreak system prompt leak indirect injection chatbot",
}
MIN_REL = float(os.environ.get("MEMORIA_MIN_REL", "0.38"))

# Deliberately OFF-TOPIC seed for the ablation's stale-memory arm (GB_MEMORIA_STALE=1):
# in-corpus so chunks clear MIN_REL and the block has the SAME shape/length as a real hint,
# but topically useless for any crAPI web/API class -> isolates relevance from format.
_STALE_SEED = ("windows active directory kerberos golden ticket ntlm relay "
               "domain controller privilege escalation mimikatz secretsdump")

def hints_for(cls, items, target="", k=3, timeout=7):
    if _memoria_query is None:
        return ""
    seed = _SEED.get(cls, cls.replace("-", " ") + " web exploitation techniques")
    # sharpen with up to 2 endpoint paths from the worklist
    eps = [it.get("endpoint", "") for it in (items or [])[:2] if it.get("endpoint")]
    if os.environ.get("GB_MEMORIA_STALE", "").strip().lower() in ("1", "on", "true", "yes"):
        q = _STALE_SEED                      # stale arm: same shape, off-topic content
    else:
        q = (seed + " " + " ".join(eps)).strip()
    try:
        res = _memoria_query(q, k * 2, timeout) or []
    except Exception:
        return ""
    picks = []
    for r in res:
        if not isinstance(r, dict):
            continue
        if float(r.get("relevance", 0) or 0) < MIN_REL:
            continue
        txt = _memoria_clean(r.get("text", ""))[:340]
        if txt:
            picks.append((float(r.get("relevance", 0)), txt))
        if len(picks) >= k:
            break
    if not picks:
        return ""
    out = ["", "## Memoria hints (corpus — advisory, verify before trusting)"]
    for rel, txt in picks:
        out.append(f"- (rel {rel:.2f}) {txt}")
    out.append("")
    return "\n".join(out)

if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--k", type=int, default=3)
    a = ap.parse_args()
    h = hints_for(a.cls, [], a.target, a.k)
    print(h or "(no hints returned — Memoria down, off-topic, or below threshold)")
