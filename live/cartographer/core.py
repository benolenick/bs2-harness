#!/usr/bin/env python3
"""cartographer — the MISSING role: the keeper of the box's live map.

The recurring failure (see gunbelt/HOW_I_BROKE_BATTLESTATION_AND_HOW_IT_SHOULD_WORK.md):
the manager holds "what's on the box AND what I haven't looked at yet" only in its context
window, which summarizes, drifts, and evaporates between steps -- so it re-enumerates
nothing and falls back to canned goals. Ariadne doesn't fix this: Ariadne plans EXPLOIT
CHAINS ("given osTicket, here's the ladder"); it has no notion of DISCOVERY frontier
("which surface haven't I mapped?"). That's a different job with no owner. This is the owner.

The map already exists in pieces (map.json = host/ports, ariadne_facts.jsonl = web surface,
a scattered "frontier" string in three files). What was missing is a single durable artifact
that tracks, per surface item, its LIFECYCLE STATE and derives the discovery frontier from it.

Design contract (deliberate, matches the postmortem's "how it SHOULD work"):
  * WRITER IS CODE, NEVER THE LLM.  fold() is deterministic. The manager cannot drift the
    map by forgetting; the map is on disk and only mutates through folded observations.
  * MANAGER READS frontier(), PICKS the top untouched edge, AUTHORS the probe itself.
    We hand it CLASSES a real pentester always checks (dirs/vhosts/shares/cve-lookup...),
    never a pre-baked "this box has bug X" decision. Discovery rituals are safe to encode
    ("always enumerate an http port's vhosts"); exploit decisions stay the manager's + Ariadne's.
  * ARIADNE IS A CONSULTANT the loop calls when the map is rich enough to plan a chain.
    fold() also emits the (apps, proven, extra_facts) triple recon_advisor wants, so the
    cartographer feeds Ariadne rather than competing with it.
  * CONTENT-BLIND.  Node labels are non-secret handles (port/product/endpoint-path/username).
    Cred secrets are never written to the ledger; only the username + a has_secret flag.

Ledger:  <run-dir>/cartography.json
CLI:     python3 -m cartographer init     --run-dir DIR [--target IP]
         python3 -m cartographer fold     --run-dir DIR [--obs FILE|-]
         python3 -m cartographer frontier --run-dir DIR [--top N] [--json]
         python3 -m cartographer show     --run-dir DIR
         python3 -m cartographer ariadne  --run-dir DIR
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import htb_observations as HO          # the Ariadne-vocabulary folder (reused, not duplicated)
except Exception:
    HO = None

from . import coverage, environment, hypotheses, report as reporting
from .model import (
    DEAD,
    ENUMERATING,
    EXHAUSTED,
    FOOTHOLD,
    LEDGER,
    OFF_FRONTIER,
    PAYOFF,
    STATE_MULT,
    UNTOUCHED,
    UNVERIFIED,
    _match,
    _match_exact,
    _node,
    _recompute_state,
    _rituals_for,
)
from recon_record import ReconObservation


# ---------------------------------------------------------------------------- #
class Cartographer:
    def __init__(self, run_dir, ledger=None):
        self.run = Path(run_dir)
        self.path = self.run / LEDGER
        self.ledger = ledger
        self._event_batch = 0
        self.doc = self._load()

    def _load(self):
        doc = None
        if self.path.exists():
            try:
                doc = json.load(open(self.path))
            except Exception:
                pass
        if not isinstance(doc, dict):
            doc = {"target": None, "updated": 0, "nodes": {}, "log": []}
        doc.setdefault("hypotheses", {})
        doc.setdefault("findings", [])
        doc.setdefault("cleanup_obligations", [])
        return doc

    def save(self, ts=None):
        self.doc["updated"] = int(ts or self.doc.get("updated") or 0)
        self.run.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        json.dump(self.doc, open(tmp, "w"), indent=2)
        os.replace(tmp, self.path)

    # ---- node helpers -----------------------------------------------------
    def _node(self, nid, kind, label, parent=None, opened_by="", meta=None, ts=0, state=None):
        return _node(self.doc, nid, kind, label, parent, opened_by, meta, ts, state)

    def add_note(self, nid, text, ts=0):
        """attach a free-form, non-structural finding (e.g. a cve-candidate title) to a node
        so it doesn't evaporate — the manager/Ariadne read these off the node it belongs to."""
        n = self.doc["nodes"].get(nid)
        if n is None:
            return
        if text not in n["notes"]:
            n["notes"].append(text)
            n["touched_ts"] = ts

    def _rituals_for(self, n):
        return _rituals_for(n)

    def _recompute_state(self, n, ts):
        return _recompute_state(n, ts)

    def _match(self, hint):
        return _match(self.doc, hint)

    # ---- ingest the host/port map that already exists ---------------------
    def ingest_map_json(self, ts=0):
        mp = self.run / "map.json"
        if not mp.exists():
            return 0
        try:
            d = json.load(open(mp))
        except Exception:
            return 0
        added = 0
        for host in d.get("hosts") or []:
            ip = host.get("ip") or host.get("host") or "target"
            if self.doc["target"] is None:
                self.doc["target"] = ip
            hid = f"host:{ip}"
            hn = self._node(hid, "host", ip, parent=None, opened_by="map.json",
                            meta={"is_dc": host.get("is_dc", False)}, ts=ts); added += 1
            # a map.json IS the product of a port sweep — that ritual is already done, so the
            # host node stops dominating the frontier over the real per-service edges.
            # full-port-sweep is done (the map proves it); internal-ports-if-shell is a
            # post-foothold action, not a discovery edge — neither belongs on the frontier now.
            for r in ("full-port-sweep", "internal-ports-if-shell"):
                if r not in hn["rituals_done"]:
                    hn["rituals_done"].append(r)
            self._recompute_state(hn, ts)
            for p in host.get("ports") or []:
                port = p.get("port"); svc = (p.get("name") or "").lower()
                prod = p.get("product") or ""
                ver = p.get("version") or ""
                svc = {"domain": "dns", "http-proxy": "http"}.get(svc, svc)
                pid = f"port:{ip}:{port}"
                self._node(pid, "port", f"{port}/{svc} {prod} {ver}".strip(), parent=hid,
                           opened_by="map.json",
                           meta={"port": port, "service": svc, "product": prod,
                                 "version": ver}, ts=ts); added += 1
        return added

    # ---- the deterministic writer ----------------------------------------
    def fold(self, observations, ts=0):
        """observations: list of scrubbed 'key=value' / prose strings (htb_observations shape),
        PLUS optional control keys that move lifecycle state:
            enum=<hint>:<ritual>   mark one ritual of a node done
            attack=<hint>:<ritual> same shape, for attack receipts (app-node rituals only)
            verified=<hint>        promote an UNVERIFIED vhost to the real frontier
            done=<hint>            mark a node exhausted
            dead=<hint>            mark a node a confirmed dead end
            foothold=<hint>|shell=..|rce=..   mark node (and host) led-to-foothold
        Returns a short change summary."""
        ts = int(ts or 0)
        if isinstance(observations, (str, ReconObservation)):
            observations = [observations]
        obs = []
        for item in observations:
            if isinstance(item, ReconObservation):
                if item.validate():
                    continue
                value = item.to_fold()
            else:
                value = str(item)
            if value.strip():
                obs.append(value)
        changed = {"nodes_added": 0, "state_changes": [], "rituals": 0, "refused": []}
        refused_obs = set()
        before = set(self.doc["nodes"])
        host_id = next((nid for nid, n in self.doc["nodes"].items() if n["kind"] == "host"), None)
        footholds = set()   # host ids that reached FOOTHOLD this fold -> open interior frontier

        def _exact(hint, o):
            """Lifecycle controls bind an EXACT stable node or fail closed (critique #4:
            fuzzy first-match can close work on the wrong node). Ambiguity/unknown is
            logged, never mutated, and surfaced in the change summary."""
            nids = _match_exact(self.doc, hint)
            if len(nids) != 1:
                why = "ambiguous" if nids else "no exact node"
                changed["refused"].append(f"{o} ({why})")
                refused_obs.add(o)
                self.doc.setdefault("log", []).append(
                    {"ts": ts, "op": "fold-refused", "obs": o, "why": why})
                return []
            return nids

        # ---- 1. lifecycle-control observations (explicit state moves) -----
        for o in obs:
            k, _, v = o.partition("=")
            k = k.strip().lower(); v = v.strip()
            if k in ("enum", "attack") and ":" in v:
                hint, ritual = v.rsplit(":", 1)
                for nid in _exact(hint, o):
                    n = self.doc["nodes"][nid]
                    # only accept rituals the node actually owns: a bogus key must not
                    # inflate coverage (fold is the ONE writer, trust nothing raw)
                    if ritual not in set(_rituals_for(n)):
                        continue
                    if ritual not in n["rituals_done"]:
                        n["rituals_done"].append(ritual); changed["rituals"] += 1
                    self._recompute_state(n, ts)
            elif k == "verified" and v:
                # a content-compare proved this vhost serves DISTINCT content: promote the
                # fuzz artifact to the real frontier (batch verify in the manager loop)
                for nid in _exact(v, o):
                    n = self.doc["nodes"][nid]
                    if n.get("kind") != "vhost" or n["state"] != UNVERIFIED:
                        continue
                    n["state"] = UNTOUCHED
                    n["meta"].pop("verify_pending", None)
                    n["touched_ts"] = ts
                    changed["state_changes"].append([nid, UNTOUCHED])
            elif k in ("done", "exhausted") and v:
                for nid in _exact(v, o):
                    self.doc["nodes"][nid]["state"] = EXHAUSTED
                    self.doc["nodes"][nid]["touched_ts"] = ts
                    changed["state_changes"].append([nid, EXHAUSTED])
            elif k == "dead" and v:
                for nid in _exact(v, o):
                    self.doc["nodes"][nid]["state"] = DEAD
                    changed["state_changes"].append([nid, DEAD])
            elif k in ("discovered-host", "reachable") and v:
                # a newly discovered/reachable internal host becomes a NEW exterior root
                hid = environment.add_discovered_host(self.doc, v, opened_via=(host_id or "pivot"), ts=ts)
                if hid:
                    changed["state_changes"].append([hid, "discovered-host"])
            elif k == "session" and v:
                # session=<sid>:<via_host>:<user>:<proto>
                parts = v.split(":")
                environment.record_session(self.doc, parts[0],
                                           via_host=parts[1] if len(parts) > 1 else "",
                                           user=parts[2] if len(parts) > 2 else "",
                                           protocol=parts[3] if len(parts) > 3 else "", ts=ts)
            elif k in ("cred-works", "auth-failed") and ":" in v:
                who, _, where = v.partition(":")
                environment.cred_applicability(self.doc, who, where,
                                               works=(k == "cred-works"), ts=ts)
            elif k in ("foothold", "shell", "rce") or re.search(r"\bwww-data\b|meterpreter|reverse shell", o, re.I):
                tgt = self._match(v)[:1] if v else []
                for nid in (tgt or ([host_id] if host_id else [])):
                    self.doc["nodes"][nid]["state"] = FOOTHOLD
                    self.doc["nodes"][nid].setdefault("notes", []).append(f"foothold@{ts}")
                    changed["state_changes"].append([nid, FOOTHOLD])
                    if self.doc["nodes"][nid]["kind"] == "host":
                        footholds.add(nid)

        # ---- 2. discovery observations via the Ariadne-vocabulary folder --
        apps, proven, extra = ({}, [], [])
        if HO is not None:
            try:
                apps, proven, extra = HO.obs_to_graph(obs)
            except Exception:
                pass

        # recognised applications -> app nodes (highest-payoff frontier: cve-lookup etc.)
        for app, ver in (apps or {}).items():
            # an IP-shaped "version" is the target suffix of an app=<name>:<ip> fact, not a
            # real version (run 746 step 1) — blank it so the recipe-first searchsploit hint
            # isn't polluted with junk tokens
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){2,3}", str(ver).strip()):
                ver = ""
            aid = f"app:{app}"
            self._node(aid, "app", f"{app} {ver}".strip(), parent=host_id,
                       opened_by="fold:app-fingerprint", meta={"app": app, "version": ver}, ts=ts)

        # endpoints -> endpoint nodes
        for f in extra or []:
            if f and f[0] == "endpoint":
                eid = f"ep:{f[1]}"
                self._node(eid, "endpoint", f[1], parent=host_id, opened_by="fold:web-surface",
                           meta={"handle": f[1]}, ts=ts)

        # signal predicates -> notes on the endpoint (a HINT the manager reads, not a decision)
        sig = [f for f in (extra or []) if f and f[0] in
               ("injectable", "nosql_injectable", "serves_file_by_param", "template_engine",
                "xxe_vulnerable", "insecure_deserialization", "reset_flow", "db_backed")]
        if sig:
            for f in sig:
                note = "signal:" + ":".join(str(x) for x in f)
                handle = str(f[1]) if len(f) > 1 else ""
                signal_node = next(
                    (n for n in self.doc["nodes"].values()
                     if n["kind"] == "endpoint"
                     and ((n.get("meta") or {}).get("handle") == handle or n["id"] == handle)),
                    None,
                ) or next(
                    (n for n in self.doc["nodes"].values() if n["kind"] in ("endpoint", "app")),
                    None,
                )
                if signal_node and note not in signal_node["notes"]:
                    signal_node["notes"].append(note)

        # creds -> cred nodes (content-blind: username + has_secret only)
        for p in proven or []:
            if p.startswith("cred=") and ":" in p:
                user = p.split("=", 1)[1].split(":", 1)[0]
                cid = f"cred:{user}"
                self._node(cid, "cred", f"{user}:****", parent=host_id, opened_by="fold:loot",
                           meta={"user": user, "has_secret": True}, ts=ts)
            elif p.startswith("shell="):
                if host_id:
                    self.doc["nodes"][host_id]["state"] = FOOTHOLD
                    footholds.add(host_id)

        # free-form discovery: vhosts / shares / users mentioned in prose.
        # Vhost facts are FUZZ ARTIFACTS until a content-compare proves the name serves
        # something other than the default site (runs 743-745: wordlist ghosts were added
        # to the frontier and re-added by every re-fuzz). They are born UNVERIFIED —
        # off the frontier, out of coverage — and only the manager loop's batch verify
        # (or a task's explicit compare) promotes a real one (verified=) or kills a ghost
        # (dead=). Re-mentioning an existing node never resurrects its lifecycle.
        for o in obs:
            for m in re.finditer(r"vhost[=: ]+([a-z0-9.\-]+)", o, re.I):
                self._node(f"vhost:{m.group(1).lower()}", "vhost", m.group(1),
                           parent=host_id, opened_by="fold:vhost", ts=ts,
                           state=UNVERIFIED, meta={"verify_pending": True})
            for m in re.finditer(r"share[=: ]+([a-z0-9$._\-]+)", o, re.I):
                self._node(f"share:{m.group(1).lower()}", "share", m.group(1),
                           parent=host_id, opened_by="fold:share", ts=ts)

        # ---- 3. a foothold OPENS the interior post-exploitation frontier on that host ----
        for hid in footholds:
            environment.open_interior_frontier(self.doc, hid, ts)

        changed["nodes_added"] = len(set(self.doc["nodes"]) - before)
        self.doc.setdefault("log", []).append(
            {"ts": ts, "n_obs": len(obs), **{k: v for k, v in changed.items() if k != "state_changes"},
             "state_changes": changed["state_changes"]})
        self.doc["log"] = self.doc["log"][-50:]
        hypotheses.raise_from_signals(self.doc, ts)
        if self.ledger is not None:
            self._event_batch += 1
            batch = f"fold-{self._event_batch}"
            for value in obs:
                key = value.partition("=")[0].strip().lower()
                if value in refused_obs:
                    kind = "refuse"
                elif key == "verified":
                    kind = "verify"
                elif key == "done":
                    kind = "done"
                elif key == "exhausted":
                    kind = "exhausted"
                elif key == "dead":
                    kind = "dead"
                else:
                    kind = "fold"
                self.ledger.append({"ts": ts, "kind": kind,
                                    "payload": {"batch": batch, "observation": value}})
        return changed

    # ---- the reader the manager loop calls every step --------------------
    def frontier(self, top=8):
        """ranked list of untouched/enumerating edges. Each row carries the CLASSES to check
        (suggest[]) -- the manager authors the actual probe. This is the discovery frontier,
        NOT Ariadne's exploit frontier."""
        rows = []
        for nid, n in self.doc["nodes"].items():
            if n["state"] in OFF_FRONTIER:
                continue
            kind = n["kind"]
            base = PAYOFF.get(n["meta"].get("service") if kind == "port" else kind, PAYOFF["_default"])
            score = base * STATE_MULT.get(n["state"], 0.0)
            rituals = self._rituals_for(n)
            todo = [r for r in rituals if r not in (n.get("rituals_done") or [])]
            # small nudge: never-touched nodes over partially-done ones at equal base
            if n["state"] == UNTOUCHED:
                score += 3
            rows.append({"id": nid, "kind": kind, "label": n["label"], "state": n["state"],
                         "score": round(score, 1), "suggest": todo,
                         "opened_by": n.get("opened_by", ""), "notes": n.get("notes", [])})
        rows.sort(key=lambda r: -r["score"])
        return rows[:top]

    def ariadne_triple(self):
        """(apps, proven, extra_facts) rebuilt from the CURRENT map, for recon_advisor.advise_from_state."""
        apps, proven, extra = {}, [], []
        for n in self.doc["nodes"].values():
            if n["kind"] == "app":
                apps[n["meta"]["app"]] = n["meta"].get("version", "")
            elif n["kind"] == "endpoint":
                extra.append(["endpoint", n["meta"]["handle"]])
                for note in n.get("notes", []):
                    if note.startswith("signal:"):
                        extra.append(note.split(":", 1)[1].split(":"))
            elif n["kind"] == "cred":
                proven.append(f"cred={n['meta']['user']}:****")
            elif n["kind"] == "host" and n["state"] == FOOTHOLD:
                proven.append("shell=www-data")
        return apps, proven, extra

    # ---- durable vulnerability-assessment register ----------------------
    def open_hypotheses(self, top=8):
        return hypotheses.open_hypotheses(self.doc, top)

    def confirmed_negatives(self):
        """Rejected hypotheses as typed Ariadne negatives: [vuln_class, locus] fact
        patterns — the same shape as positive signal facts — so Ariadne hard-prunes
        branches that were tested AND rejected instead of re-proposing them every turn
        (critique #8: negatives=None means rejected assumptions keep coming back).
        Inconclusive stays OUT: 'we could not decide' is not a confirmed negative."""
        out = []
        for hyp in (self.doc.get("hypotheses") or {}).values():
            if hyp.get("status") != "rejected":
                continue
            cls = str(hyp.get("vuln_class") or "").strip()
            locus = str(hyp.get("node") or hyp.get("locus") or "").strip()
            if cls:
                out.append([cls, locus])
        return out

    def set_testing(self, id, ts, note=""):
        return hypotheses.set_testing(self.doc, id, ts, note)

    def resolve_hypothesis(self, id, verdict, evidence_refs, reason, ts):
        return hypotheses.resolve(self.doc, id, verdict, evidence_refs, reason, ts)

    def findings(self):
        return self.doc["findings"]

    # ---- derived cross-phase completion view -----------------------------
    def coverage_report(self, scope=None):
        return coverage.coverage_report(self.doc, scope)

    def coverage_render(self, scope=None):
        return coverage.render(self.doc, scope)

    # ---- proof -> finding -> report -> remediation -> retest closure -----
    def finding_packages(self, run_dir):
        telemetry_index = reporting.load_telemetry(run_dir)
        return [
            reporting.finding_package(self.doc, finding, telemetry_index)
            for finding in sorted(
                self.doc.get("findings", []),
                key=lambda row: str(row.get("id") or ""),
            )
        ]

    def engagement_report(self, run_dir, scope=None):
        return reporting.engagement_report(self.doc, run_dir, scope)

    def engagement_markdown(self, run_dir, scope=None):
        return reporting.render_markdown(self.engagement_report(run_dir, scope))

    def retest_finding(self, fid, result, note="", ts=0):
        return reporting.retest_finding(self.doc, fid, result, note, ts)

    # ---- P1-6 terminal projection (the ONLY closed-state vocabulary) -----------
    def terminal_projection(self, scope=None, stopped=False):
        return coverage.terminal_projection(self.doc, scope, stopped)

    # ---- P1-1: cartography.json is a DISPOSABLE export --------------------------
    @classmethod
    def rebuild_from_events(cls, run_dir, telemetry_path=None, map_json_path=None):
        """Rebuild the map from the CANONICAL event stream (telemetry.jsonl) + map.json:
        replay seeded/folded facts, vhost verdicts, hypotheses, verdicts, autoturret
        facts, and stop folds in event order. The events are the authority; this file
        is a cache. A projection failure mid-replay raises — consumers must not
        advance past the event head they successfully processed."""
        run_dir = Path(run_dir)
        telemetry_path = Path(telemetry_path) if telemetry_path \
            else run_dir / "telemetry.jsonl"
        map_json_path = Path(map_json_path) if map_json_path \
            else run_dir / "map.json"
        c = cls(str(run_dir))
        if map_json_path.exists():
            c.ingest_map_json(0)
        for line in telemetry_path.read_text().splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue   # torn tail lines are skipped; structural errors raise below
            kind = row.get("event")
            step = int(row.get("step", 0) or 0)
            if kind in ("seeded", "ran", "autoturret") and row.get("folded_facts"):
                c.fold(list(row["folded_facts"]), ts=step)
            elif kind == "vhost_verify":
                c.fold([f"dead={g}" for g in row.get("ghosts") or []] +
                       [f"verified={r}" for r in row.get("reals") or []], ts=step)
            elif kind == "stop" and row.get("folded"):
                c.fold(list(row["folded"]), ts=step)
            elif kind == "hypothesis_raised" and row.get("hypothesis_id"):
                hid = row["hypothesis_id"]
                if hid in c.doc.get("hypotheses", {}):
                    continue
                hypotheses.raise_hypothesis(
                    c.doc, node=row.get("node"), vuln_class=row.get("vuln_class"),
                    locus=row.get("locus"), title=row.get("title", ""),
                    raised_from=list(row.get("raised_from")
                                     or [row.get("source", "events")]),
                    confidence=row.get("confidence", "low"),
                    required_validation=row.get("required_validation"),
                    impact=row.get("impact", ""), severity=row.get("severity", "medium"),
                    ts=step)
            elif kind == "verdict" and row.get("hypothesis_id"):
                hid = row["hypothesis_id"]
                verdict = row.get("verdict")
                hyp = c.doc.get("hypotheses", {}).get(hid)
                if hyp is None or verdict not in ("confirmed", "rejected",
                                                  "inconclusive"):
                    continue
                if hyp.get("status") == "proposed":
                    c.set_testing(hid, step, "replayed from events")
                c.resolve_hypothesis(hid, verdict, list(row.get("evidence_refs") or []),
                                    row.get("reason", ""), step)
        c.save(0)
        return c

    # ---- environment (multi-host / post-foothold / lateral) topology -----
    def environment_map(self):
        return environment.environment_map(self.doc)

    def environment_render(self):
        return environment.render(self.doc)

    # ---- human view -------------------------------------------------------
    def render(self):
        nodes = self.doc["nodes"]
        by_parent = {}
        for n in nodes.values():
            by_parent.setdefault(n.get("parent"), []).append(n)
        sym = {UNTOUCHED: "· ", ENUMERATING: "~ ", EXHAUSTED: "✓ ", FOOTHOLD: "★ ", DEAD: "✗ "}
        out = [f"cartography  target={self.doc.get('target')}  nodes={len(nodes)}  updated={self.doc.get('updated')}"]
        def walk(pid, depth):
            for n in sorted(by_parent.get(pid, []), key=lambda x: x["id"]):
                todo = [r for r in self._rituals_for(n) if r not in (n.get("rituals_done") or [])]
                tail = f"   todo:{','.join(todo)}" if todo and n["state"] not in OFF_FRONTIER else ""
                out.append("  " * depth + sym.get(n["state"], "? ") + f"{n['label']}  [{n['state']}]" + tail)
                walk(n["id"], depth + 1)
        walk(None, 0)
        return "\n".join(out)


# ---------------------------------------------------------------------------- #
def _read_obs(src):
    if not src:
        return []
    text = sys.stdin.read() if src == "-" else open(src).read()
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # allow a JSON array of strings, else one obs per line
        if line.startswith("["):
            try:
                out.extend(str(x) for x in json.loads(line)); continue
            except Exception:
                pass
        out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser(description="cartographer — keeper of the box's live map")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("init", "fold", "frontier", "show", "ariadne"):
        s = sub.add_parser(c); s.add_argument("--run-dir", required=True)
        if c == "init":
            s.add_argument("--target")
        if c == "fold":
            s.add_argument("--obs", default="-", help="file of observations, or - for stdin")
        if c == "frontier":
            s.add_argument("--top", type=int, default=8); s.add_argument("--json", action="store_true")
    a = ap.parse_args()
    ts = int(os.environ.get("CARTO_TS", "0"))          # deterministic in tests; caller stamps real time
    C = Cartographer(a.run_dir)

    if a.cmd == "init":
        if a.target:
            C.doc["target"] = a.target
        n = C.ingest_map_json(ts)
        C.save(ts)
        print(f"seeded {n} node-updates from map.json  ->  {C.path}")
    elif a.cmd == "fold":
        if not C.doc["nodes"]:
            C.ingest_map_json(ts)
        ch = C.fold(_read_obs(a.obs), ts)
        C.save(ts)
        print(json.dumps(ch))
    elif a.cmd == "frontier":
        fr = C.frontier(a.top)
        if a.json:
            print(json.dumps(fr, indent=2))
        else:
            print(f"# discovery frontier (top {a.top}) — manager picks one, authors the probe:")
            for r in fr:
                print(f"  {r['score']:6.1f}  {r['kind']:8} {r['label'][:44]:44}  → {', '.join(r['suggest'][:4])}")
            if not fr:
                print("  (frontier dry — every surface item exhausted/foothold/dead)")
    elif a.cmd == "show":
        print(C.render())
    elif a.cmd == "ariadne":
        apps, proven, extra = C.ariadne_triple()
        print(json.dumps({"apps": apps, "proven": proven, "extra_facts": extra}, indent=2))


__all__ = ["Cartographer", "main"]
