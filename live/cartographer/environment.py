"""Environment Cartographer: durable post-exploitation frontier + lateral-movement topology.

Single-host discovery answers "what surface haven't I mapped on THIS host?".  Once a foothold
lands, two new questions have no owner:

  * POST-EXPLOITATION — a foothold should OPEN a fresh interior discovery frontier on that host
    (who am I / local services / privesc paths / what networks can I now see), not just mark the
    external node done.
  * LATERAL MOVEMENT — a discovered internal host should become a NEW Cartographer root with its
    own exterior frontier, and we must durably track the pivot/credential topology (which identity
    works where, via which session, and where it was rejected).

Same contract as the rest of the package: this is a DETERMINISTIC writer/reader over ``doc``.
It never chooses work, contacts a target, or writes secrets — credential nodes carry a username
and applicability lists only.  The manager reads ``environment_map`` and authors every command.
"""

from __future__ import annotations

from .model import FOOTHOLD, UNTOUCHED, OFF_FRONTIER, _node, _rituals_for


# interior node kinds a foothold opens, in the order they matter to an operator
_INTERIOR = ("identity", "localenum", "privesc", "netview")


def _host_ip(doc, host_id):
    n = (doc.get("nodes") or {}).get(host_id) or {}
    return (n.get("meta") or {}).get("ip") or n.get("label") or (host_id or "").split(":", 1)[-1]


def open_interior_frontier(doc, host_id, ts=0):
    """Spawn (idempotently) the interior post-foothold child nodes under a FOOTHOLD host.

    The host node keeps its FOOTHOLD state; the interior nodes are fresh UNTOUCHED frontier."""
    if not host_id or host_id not in (doc.get("nodes") or {}):
        return []
    ip = _host_ip(doc, host_id)
    added = []
    for kind in _INTERIOR:
        nid = f"{kind}:{ip}"
        if nid not in doc["nodes"]:
            added.append(nid)
        _node(doc, nid, kind, f"{kind}@{ip}", parent=host_id,
              opened_by="foothold", meta={"host": ip}, ts=ts)
    return added


def add_discovered_host(doc, ip, opened_via="pivot", ts=0):
    """Create a new exterior host root for a newly discovered/reachable internal host.

    The new host gets the normal exterior discovery frontier (host RITUALS: full-port-sweep,
    passive-dns, ...); a later port sweep folds its per-service edges.  Idempotent."""
    ip = str(ip).strip()
    if not ip:
        return None
    hid = f"host:{ip}"
    fresh = hid not in doc["nodes"]
    _node(doc, hid, "host", ip, parent=None, opened_by=opened_via,
          meta={"ip": ip, "discovered_via": opened_via}, ts=ts)
    if fresh:
        # a discovered host has NOT been port-swept yet — unlike the ingested origin host, its
        # full-port-sweep is a genuine open edge, so leave rituals_done empty (fresh frontier).
        doc["nodes"][hid]["state"] = UNTOUCHED
    return hid


def record_session(doc, sid, via_host="", user="", protocol="", ts=0):
    """Upsert a session node — a durable record of a live foothold/pivot channel."""
    sid = str(sid).strip()
    if not sid:
        return None
    nid = f"session:{sid}"
    _node(doc, nid, "session", f"session {sid} ({user or '?'}@{via_host or '?'}/{protocol or '?'})",
          parent=(f"host:{via_host}" if via_host else None), opened_by="pivot",
          meta={"sid": sid, "via_host": via_host, "user": user, "protocol": protocol}, ts=ts)
    return nid


def cred_applicability(doc, user, host, works, ts=0):
    """Record where a credential works / was rejected.  Negative (failed) evidence is retained —
    it informs lockout risk and blast-radius.  Creates the cred node if missing (content-blind)."""
    user = str(user).strip()
    host = str(host).strip()
    if not user or not host:
        return None
    cid = f"cred:{user}"
    n = _node(doc, cid, "cred", f"{user}:****", parent=None, opened_by="fold:loot",
              meta={"user": user, "has_secret": True}, ts=ts)
    meta = n["meta"]
    works_on = meta.setdefault("works_on", [])
    failed_on = meta.setdefault("failed_on", [])
    tgt, other = (works_on, failed_on) if works else (failed_on, works_on)
    if host not in tgt:
        tgt.append(host)
    if host in other:                       # latest evidence wins if it flips
        other.remove(host)
    n["touched_ts"] = ts
    return cid


# --------------------------------------------------------------------------- readers
def _subtree_ids(doc, root_id):
    """all node ids whose parent-chain reaches root_id (inclusive)."""
    kids = {root_id}
    changed = True
    while changed:
        changed = False
        for nid, n in (doc.get("nodes") or {}).items():
            if nid not in kids and n.get("parent") in kids:
                kids.add(nid); changed = True
    return kids


def environment_map(doc):
    nodes = doc.get("nodes") or {}
    hosts, sessions, credentials, reachable = [], [], [], []
    frontier_by_host = {}

    host_ids = [nid for nid, n in nodes.items() if n.get("kind") == "host"]
    for hid in sorted(host_ids):
        n = nodes[hid]
        ip = (n.get("meta") or {}).get("ip") or n.get("label") or hid.split(":", 1)[-1]
        hosts.append({"id": hid, "ip": ip, "state": n.get("state"),
                      "opened_by": n.get("opened_by", "")})
        if n.get("opened_by") and n.get("opened_by") not in ("map.json", ""):
            reachable.append({"via_session_or_host": n.get("opened_by"), "to_host": ip})
        # distinct open suggest classes anywhere in this host's subtree
        classes = []
        for kid in _subtree_ids(doc, hid):
            kn = nodes.get(kid) or {}
            if kn.get("state") in OFF_FRONTIER:
                continue
            for r in _rituals_for(kn):
                if r not in (kn.get("rituals_done") or []) and r not in classes:
                    classes.append(r)
        frontier_by_host[ip] = classes

    for nid, n in sorted(nodes.items()):
        if n.get("kind") == "session":
            m = n.get("meta") or {}
            sessions.append({"id": nid, "via_host": m.get("via_host", ""),
                             "user": m.get("user", ""), "protocol": m.get("protocol", "")})
            if m.get("via_host"):
                reachable.append({"via_session_or_host": nid, "to_host": m.get("via_host")})
        elif n.get("kind") == "cred":
            m = n.get("meta") or {}
            credentials.append({"user": m.get("user", nid.split(":", 1)[-1]),
                                "works_on": list(m.get("works_on") or []),
                                "failed_on": list(m.get("failed_on") or [])})

    return {"hosts": hosts, "sessions": sessions, "reachable": reachable,
            "credentials": credentials, "frontier_by_host": frontier_by_host}


def render(doc):
    em = environment_map(doc)
    lines = [f"environment  hosts={len(em['hosts'])}  sessions={len(em['sessions'])}"
             f"  creds={len(em['credentials'])}"]
    for h in em["hosts"]:
        fr = em["frontier_by_host"].get(h["ip"]) or []
        via = f"  via {h['opened_by']}" if h["opened_by"] not in ("map.json", "") else ""
        tail = f"   open:{','.join(fr[:6])}" if fr else "   (frontier dry)"
        lines.append(f"  host {h['ip']} [{h['state']}]{via}{tail}")
    for s in em["sessions"]:
        lines.append(f"  session {s['id']}  {s['user']}@{s['via_host']}/{s['protocol']}")
    for c in em["credentials"]:
        lines.append(f"  cred {c['user']}  works_on={c['works_on'] or '-'}  failed_on={c['failed_on'] or '-'}")
    return "\n".join(lines)


__all__ = [
    "open_interior_frontier",
    "add_discovered_host",
    "record_session",
    "cred_applicability",
    "environment_map",
    "render",
]
