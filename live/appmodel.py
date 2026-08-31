#!/usr/bin/env python3
"""appmodel — the SHARED application model (BS2 design doc §1, 2026-08-25).

The winning difference over the MIT harness: every specialist reads ONE rich application
graph instead of rediscovering the app per agent. This module is the typed core of that
graph — endpoints, objects and ownership, identities, workflows, session boundaries, and
the previously-tested/negative ledger hooks. It is DATA + deterministic folds, never an
LLM: specialists, the differential engine, and the scheduler all read from here.

Shapes (the §1 case file, generalized):

  endpoint:  {id, method, scheme, vhost, port, route_template, params, auth_state,
             roles, object_type, ownership_fields, responses: {principal: digest}}
  object:    {id, type, owner, endpoint_id, fields}          # ownership relationships
  principal: {id, kind, sessions, enrollment}                # identities (creds live in the
                                                              # vault, never here)
  workflow:  {id, states, transitions: [{from, to, via, requires}]}

Fold vocabulary (typed, closed — no free-text guessing):

  endpoint=<method> <route> [vhost=..] [params=a,b] [auth=..] [object_type=..]
  object=<type>:<id> [owner=..] [endpoint_id=..]
  workflow=<name> <s0>-><s1>[-><s2>..] [via=<endpoint_id>]
  identity=<kind>:<name> [session=..]
"""
from __future__ import annotations
import json, os, re
from pathlib import Path


def _ep_id(appmodel, n):
    return f"ep-{n}"


class ApplicationModel:
    def __init__(self, run_dir=None):
        self.run_dir = Path(run_dir) if run_dir else None
        self.version = 0                 # bumped on every fold; experiment ledger keys off it
        self.target = None
        self.endpoints = {}              # id -> endpoint record
        self.objects = {}                # "<type>:<oid>" -> object record
        self.principals = {}             # id -> principal record
        self.workflows = {}              # name -> workflow record

    # ---- persistence ---------------------------------------------------------
    def save(self):
        if not self.run_dir:
            return
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / "appmodel.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "version": self.version, "target": self.target,
            "endpoints": self.endpoints, "objects": self.objects,
            "principals": self.principals, "workflows": self.workflows}, indent=1))
        os.replace(tmp, path)
        try: os.chmod(path, 0o600)
        except Exception: pass

    @classmethod
    def load(cls, run_dir):
        m = cls(run_dir)
        path = Path(run_dir) / "appmodel.json"
        if path.exists():
            d = json.loads(path.read_text())
            m.version = d.get("version", 0); m.target = d.get("target")
            m.endpoints = d.get("endpoints", {}); m.objects = d.get("objects", {})
            m.principals = d.get("principals", {}); m.workflows = d.get("workflows", {})
        return m

    # ---- typed folds ---------------------------------------------------------
    def fold(self, observations, ts=0):
        """Ingest closed-vocabulary observation strings. Unknown shapes are ignored
        (typed contract: nothing is guessed). Returns count of accepted observations."""
        accepted = 0
        for o in (observations or []):
            o = str(o).strip()
            if not o or "=" not in o:
                continue
            key, _, val = o.partition("=")
            key = key.strip().lower()
            try:
                if key == "endpoint":
                    accepted += self._fold_endpoint(val.strip())
                elif key == "object":
                    accepted += self._fold_object(val.strip())
                elif key == "workflow":
                    accepted += self._fold_workflow(val.strip())
                elif key == "identity":
                    accepted += self._fold_identity(val.strip())
            except Exception:
                continue
        if accepted:
            self.version += 1
        return accepted

    def _fold_endpoint(self, val):
        # endpoint=PATCH /api/accounts/{id} vhost=api.bank.local params=email,status auth=user object_type=account
        m = re.match(r"(\w+)\s+(\S+)(.*)$", val)
        if not m:
            return 0
        method, route, rest = m.group(1).upper(), m.group(2), m.group(3)
        meta = dict(re.findall(r"(\w+)=([^,\s]+)", rest))
        eid = None
        # an endpoint refold on the same method+route updates rather than duplicates
        for id_, ep in self.endpoints.items():
            if ep["method"] == method and ep["route_template"] == route:
                eid = id_
                break
        if eid is None:
            eid = _ep_id(self, len(self.endpoints) + 1)
            self.endpoints[eid] = {
                "id": eid, "method": method, "route_template": route,
                "scheme": "", "vhost": meta.get("vhost", ""), "port": None,
                "params": [p for p in meta.get("params", "").split(",") if p],
                "auth_state": meta.get("auth", "unknown"),
                "roles": meta.get("roles", "").split(",") if meta.get("roles") else [],
                "object_type": meta.get("object_type", ""),
                "ownership_fields": [], "responses": {},
            }
        else:
            ep = self.endpoints[eid]
            if meta.get("vhost"):
                ep["vhost"] = meta["vhost"]
            if meta.get("auth"):
                ep["auth_state"] = meta["auth"]
            if meta.get("object_type"):
                ep["object_type"] = meta["object_type"]
        return 1

    def _fold_object(self, val):
        # object=account:205 owner=user-b endpoint_id=ep-3
        m = re.match(r"([^:\s]+):(\S+)(.*)$", val)
        if not m:
            return 0
        otype, oid, rest = m.group(1), m.group(2), m.group(3)
        meta = dict(re.findall(r"(\w+)=([^,\s]+)", rest))
        key = f"{otype}:{oid}"
        rec = self.objects.setdefault(key, {"id": key, "type": otype, "oid": oid,
                                            "owner": None, "endpoint_id": None, "fields": []})
        rec["owner"] = meta.get("owner", rec["owner"])
        rec["endpoint_id"] = meta.get("endpoint_id", rec["endpoint_id"])
        return 1

    def _fold_workflow(self, val):
        # workflow=transfer draft->approval->execution->settlement via=ep-9
        m = re.match(r"([A-Za-z0-9_-]+)\s+([\w-]+(?:->[\w-]+)+)(?:\s+via=(\S+))?$", val)
        if not m:
            return 0
        name, chain, via = m.group(1), m.group(2).split("->"), m.group(3)
        wf = self.workflows.setdefault(name, {"id": name, "states": [], "transitions": []})
        wf["states"] = sorted(set(wf["states"]) | set(chain))
        for a, b in zip(chain, chain[1:]):
            tr = {"from": a, "to": b, "via": via or ""}
            if tr not in wf["transitions"]:
                wf["transitions"].append(tr)
        return 1

    def _fold_identity(self, val):
        # identity=user:alice session=s-1  (kind: user/privileged/tenant/expired/mfa_partial/anon)
        m = re.match(r"([\w-]+):(\S+)(.*)$", val)
        if not m:
            return 0
        kind, name, rest = m.group(1), m.group(2), m.group(3)
        meta = dict(re.findall(r"(\w+)=([^,\s]+)", rest))
        pid = f"{kind}:{name}"
        rec = self.principals.setdefault(pid, {"id": pid, "kind": kind, "name": name,
                                               "sessions": [], "enrollment": ""})
        if meta.get("session") and meta["session"] not in rec["sessions"]:
            rec["sessions"].append(meta["session"])
        if meta.get("enrollment"):
            rec["enrollment"] = meta["enrollment"]
        return 1

    # ---- derived views for the scheduler --------------------------------------
    def templated_endpoints(self):
        """Endpoints whose route carries an {id}-style template — the BOLA/BOPLA surface."""
        return [ep for ep in self.endpoints.values()
                if re.search(r"\{[^}]+\}", ep.get("route_template", ""))]

    def distinct_principals(self, kinds=None):
        """Principals for differential matrices; two same-kind principals enable
        cross-ownership testing, cross-kind principals enable role testing."""
        ps = [p for p in self.principals.values()
              if not kinds or p.get("kind") in kinds]
        return sorted(ps, key=lambda p: p["id"])

    def objects_for(self, owner=None, otype=None):
        return sorted(
            (o for o in self.objects.values()
             if (owner is None or o.get("owner") == owner)
             and (otype is None or o.get("type") == otype)),
            key=lambda o: o["id"])


__all__ = ["ApplicationModel"]
