"""Provenance & staleness helpers for Cairn.

Every durable unit carries an `as_of` stamp and a `source` pointer so a consumer can
CHEAPLY RE-VERIFY a recalled fact before acting on it (a recalled fact is a snapshot).
Precedence the consumer must honour: live-file-on-disk > folded fact > narrative summary.
"""
from __future__ import annotations
import os
import socket
import datetime as _dt
from typing import Optional


def now_iso() -> str:
    """UTC ISO-8601 to the second. (Real wall clock; this is app code, not a workflow script.)"""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def age_seconds(as_of: Optional[str]) -> Optional[float]:
    if not as_of:
        return None
    try:
        t = _dt.datetime.fromisoformat(as_of)
        if t.tzinfo is None:
            t = t.replace(tzinfo=_dt.timezone.utc)
        return (_dt.datetime.now(_dt.timezone.utc) - t).total_seconds()
    except Exception:
        return None


def age_label(as_of: Optional[str]) -> str:
    s = age_seconds(as_of)
    if s is None:
        return "as-of ?"
    if s < 90:
        return "as-of now"
    if s < 5400:
        return f"as-of {int(s // 60)}m ago"
    if s < 172800:
        return f"as-of {int(s // 3600)}h ago"
    return f"as-of {int(s // 86400)}d ago"


def verify_source(source: Optional[str]) -> Optional[bool]:
    """Cheap existence check for a source pointer, so a slice can be re-checked before use.

    Understands:
      file:/abs/path            -> os.path.exists
      file:/abs/path:LINE       -> path exists AND has >= LINE lines
      port:HOST:PORT            -> TCP connect succeeds
    Returns True/False, or None when the pointer is not a checkable kind (event:, sigil:, url:).
    """
    if not source:
        return None
    try:
        if source.startswith("file:"):
            rest = source[5:]
            line = None
            # split a trailing :NNN line number off an absolute path
            if ":" in rest[3:]:
                head, _, tail = rest.rpartition(":")
                if tail.isdigit():
                    rest, line = head, int(tail)
            if not os.path.exists(rest):
                return False
            if line is not None:
                try:
                    with open(rest, "r", errors="replace") as fh:
                        return sum(1 for _ in fh) >= line
                except Exception:
                    return False
            return True
        if source.startswith("port:"):
            _, host, port = source.split(":", 2)
            with socket.create_connection((host, int(port)), timeout=2):
                return True
    except Exception:
        return False
    return None
