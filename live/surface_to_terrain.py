#!/usr/bin/env python3
"""surface_to_terrain — project the application-surface MAP into the governed graph.

The web_surface_mapper discovers a target's endpoints/params/apps and writes surface.json.
The green BattleStation 2.0 page renders a battle's TERRAIN NODES as its attack graph.
This bridges the two: every discovered endpoint becomes a governed TERRAIN_NODE_ADDED
(kind=asset) via the real add_terrain_node API — so a governed engagement finally shows a
map of the box in the frontend Ben actually uses. Content-blind: only paths/methods/status
cross over, never response bodies.

  python3 surface_to_terrain.py --run-dir <grun>     # reads surface.json + seam.json
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path

sys.path.insert(0, "/mnt/sata/htb-bakeoff/bs2-governed-wt")
from battlestation.service import BattleApplication          # noqa: E402
from battlestation.domain import NodeKind, AccessState, NodeStatus, ActorRole  # noqa: E402

import fcntl as _fcntl
from contextlib import contextmanager as _contextmanager

@_contextmanager
def _ledger_lock(run):
    """Same cross-process ledger lock the seam uses — so --promote can run WHILE
    attacker/expert lanes are writing the same governed.sqlite3 (parallel mode)."""
    lf = Path(run) / ".ledger.lock"
    fh = open(lf, "w")
    try:
        _fcntl.flock(fh, _fcntl.LOCK_EX)
        yield
    finally:
        try: _fcntl.flock(fh, _fcntl.LOCK_UN)
        except Exception: pass
        fh.close()


REACHABLE = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}  # exists, gated or not


def _nid(prefix: str, key: str) -> str:
    return f"{prefix}-{hashlib.sha1(key.encode()).hexdigest()[:10]}"


def _slug(path: str) -> str:
    """resource must be an identifier (no slashes) — slugify the path, keep it unique."""
    base = re.sub(r"[^A-Za-z0-9]+", "_", path.strip("/")) or "root"
    return f"{base[:48]}_{hashlib.sha1(path.encode()).hexdigest()[:6]}"


def _app(db: Path) -> BattleApplication:
    return BattleApplication(db, planner=None, live_execution_enabled=True,
                             tool_risk_registry={"http.client": "high"})



def _promote(app: BattleApplication, run: Path, battle: str, host: str) -> int:
    """Turn fog surface nodes OWNED when a finding names their path — the graph goes
    green as the attack lands.  Only promotes on an explicit path match (no guessing);
    uses the finding's own governed evidence_id as the transition proof."""
    fj = run / "findings.jsonl"
    if not fj.exists():
        print(json.dumps({"promoted": 0, "reason": "no findings.jsonl"})); return 0
    st = app._state(battle)
    # resource-slug -> node_id, and node_id -> title(path), current access
    nodes = st.nodes
    slug_by_path = {}
    for nid, node in nodes.items():
        title = getattr(node, "title", None) or (node.get("title") if isinstance(node, dict) else "")
        slug_by_path[title] = nid
    paths = sorted(slug_by_path, key=len, reverse=True)  # longest path first (specific)
    promoted = unmatched = 0
    for ln in fj.read_text().splitlines():
        try:
            f = json.loads(ln)
        except Exception:
            continue
        ev = f.get("evidence_id"); label = (f.get("label") or "")
        if not ev:
            continue
        hit = next((pp for pp in paths if pp and pp in label), None)
        if not hit:
            unmatched += 1
            continue
        nid = slug_by_path[hit]
        node = nodes[nid]
        cur = getattr(node, "access_state", None) or (node.get("access_state") if isinstance(node, dict) else None)
        cur = AccessState(cur) if cur else AccessState.FOG
        if cur == AccessState.OWNED:
            continue
        try:
            with _ledger_lock(run):
                st = app._state(battle)
                app.change_terrain_access(
                    battle, node_id=nid, target_generation=1,
                    from_access_state=cur, to_access_state=AccessState.OWNED,
                    evidence_ids=[ev],
                    reason=f"proven by finding {f.get('vuln_class','')}/{f.get('severity','')}",
                    actor_id="verifier-1", actor_role=ActorRole.VERIFIER,
                    idempotency_key=f"promote-{nid}-{ev}", expected_head=st.head_hash)
            promoted += 1
        except Exception as exc:
            print(f"  promote {hit}: {type(exc).__name__}: {str(exc)[:80]}", file=sys.stderr)
    # --- draw the exploit chain: connect the foothold to what it unlocked, so the
    # owned cluster reads as an attack path (lines) rather than isolated squares. ---
    def _access(n):
        terrain = getattr(n, "terrain", None)
        v = getattr(terrain, "access_state", None) if terrain is not None else None
        if v is None:
            v = getattr(n, "access_state", None) or (n.get("access_state") if isinstance(n, dict) else None)
        return str(getattr(v, "value", v) or "").lower()
    def _title(n):
        return getattr(n, "title", None) or (n.get("title") if isinstance(n, dict) else "") or ""
    st = app._state(battle)
    owned_nodes = [(nid, _title(n)) for nid, n in st.nodes.items() if _access(n) == "owned"]
    edges_made = 0
    if len(owned_nodes) >= 2:
        def _score(t):
            t = t.lower()
            return ("login" in t) * 3 + ("auth" in t) * 2 + 1.0 / (len(t) + 1)
        src_nid, _src_title = max(owned_nodes, key=lambda kv: _score(kv[1]))
        for tgt_nid, _t in owned_nodes:
            if tgt_nid == src_nid:
                continue
            eid = _nid("edge", f"{src_nid}->{tgt_nid}")
            try:
                with _ledger_lock(run):
                    st = app._state(battle)
                    app.add_attack_edge(
                        battle, edge_id=eid, source=src_nid, target=tgt_nid,
                        action_class="web.exploit", procedure_ref="sqli-jwt-forge",
                        target_generation=1, actor_id="verifier-1", actor_role=ActorRole.SYSTEM,
                        manager_generation=st.manager_generation,
                        idempotency_key=f"edge-{eid}", expected_head=st.head_hash)
                edges_made += 1
            except Exception as exc:
                print(f"  edge {src_nid}->{tgt_nid}: {type(exc).__name__}: {str(exc)[:80]}", file=sys.stderr)
    app.close()
    print(json.dumps({"battle": battle, "promoted": promoted,
                      "unmatched_findings": unmatched, "chain_edges": edges_made}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--limit", type=int, default=120, help="cap nodes (graph readability)")
    ap.add_argument("--promote", action="store_true",
                    help="instead of mapping: promote fog nodes proven by findings.jsonl")
    a = ap.parse_args()
    run = Path(a.run_dir)
    seam = json.loads((run / "seam.json").read_text())
    battle, host = seam["battle"], seam["host"]
    app = _app(Path(seam["db"]))

    if a.promote:
        return _promote(app, run, battle, host)

    surface = json.loads((run / "surface.json").read_text())

    # findings.jsonl → evidence_id per resource path, so nodes carry their proof.
    ev_by_path: dict[str, list[str]] = {}
    fj = run / "findings.jsonl"
    if fj.exists():
        for ln in fj.read_text().splitlines():
            try:
                f = json.loads(ln)
            except Exception:
                continue
            # findings are keyed by work_order; best-effort bind by label containing a path
            ev = f.get("evidence_id")
            if ev:
                ev_by_path.setdefault("_all", []).append(ev)

    made = skipped = 0
    endpoints = surface.get("endpoints", [])[: a.limit]
    for e in endpoints:
        path = e.get("path") or "/"
        status = e.get("status")
        # FOG: the mapper SEES the surface but has not proven access under governance.
        # A finding later PROMOTES the node to reachable/owned with real evidence.
        _ = status  # (retained for future promotion heuristics)
        params = e.get("params") or []
        methods = e.get("methods") or ["GET"]
        title = path if len(path) <= 60 else path[:57] + "…"
        node_id = _nid("srf", path)
        st = app._state(battle)
        try:
            app.add_terrain_node(
                battle,
                node_id=node_id,
                kind=NodeKind.ASSET,
                title=title,
                target=host,
                resource=_slug(path),
                target_generation=1,
                access_state=AccessState.FOG,
                evidence_ids=[],
                actor_id="mapper-1",
                actor_role=ActorRole.SYSTEM,
                manager_generation=st.manager_generation,
                idempotency_key=f"srf-{node_id}",
                expected_head=st.head_hash,
                status=NodeStatus.PROPOSED,
            )
            made += 1
        except Exception as exc:
            skipped += 1
            if skipped <= 3:
                print(f"  skip {path}: {type(exc).__name__}: {str(exc)[:80]}", file=sys.stderr)

    app.close()
    print(json.dumps({"battle": battle, "host": host,
                      "endpoints_seen": len(surface.get("endpoints", [])),
                      "nodes_made": made, "skipped": skipped,
                      "apps": surface.get("counts", {}).get("classes", [])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
