"""Cairn adapter: observations stay observations; models cannot verify findings.

Each session has its own Cairn database. Qualified receipt IDs survive restart,
and equal sequence numbers in different assessments never collide.
"""
import json
import os
import time
from dataclasses import asdict
from cairn import CairnStore, Assembler
from .journal import Journal, digest, canonical


class BattleMemory:
    def __init__(self, directory):
        self.journal = Journal(directory)
        self.entity = "battle:" + self.journal.battle_id

    def fold(self):
        store = CairnStore(str(self.journal.directory / "cairn.sqlite3"))
        os.chmod(store.db_path, 0o600)
        try:
            for row in self.journal.events():
                kind, p = row["kind"], row["payload"]
                source = f"{self.entity}:event:{row['seq']}:{row['hash']}"
                status, layer, item_kind = "hypothesis", "history", "event"
                if kind == "observation":
                    status, layer, item_kind = "verified", "state", "fact"
                    content = f"Observed {p['method']} {p.get('endpoint', p['request_key'][:16])}: HTTP {p['status']}; principal={p['principal']}. Not a vulnerability verdict."
                elif kind == "verification":
                    status = "verified" if p["verdict"] in ("confirmed", "negative") else "hypothesis"
                    layer = "negative" if p["verdict"] == "negative" else "state"
                    item_kind = "negative" if layer == "negative" else "fact" if status == "verified" else "thread"
                    content = canonical(p)
                elif kind in ("hypothesis", "decision", "inconclusive"):
                    item_kind = "thread"
                    content = canonical(p)
                else:
                    continue
                store.fold(self.entity, content, item_kind, layer=layer, status=status,
                           source=source, fold_key=source, value=8 if layer == "negative" else 5)
            return store
        except BaseException:
            store.close()
            raise

    def retry(self, action_key, conditions):
        negatives = [r for r in self.journal.events() if r["kind"] == "verification"
                     and r["payload"].get("verdict") == "negative"
                     and r["payload"].get("action_key") == action_key]
        if not negatives:
            return {"suppress": False, "reason": "No controlled negative for this check", "changed": []}
        previous = negatives[-1]["payload"]["conditions"]
        missing = sorted(set(previous) - set(conditions))
        if missing:
            return {"suppress": False, "reason": "Current conditions incomplete; revalidate before retry", "changed": [],
                    "unknown": missing, "source_seq": negatives[-1]["seq"]}
        changed = sorted(k for k in set(previous) | set(conditions) if previous.get(k) != conditions.get(k))
        if time.time() - negatives[-1]["ts"] > 86400:
            changed.append("evidence_age_over_24h")
        return {"suppress": not changed, "reason": "Conditions changed; re-check" if changed else "Already disproved under identical conditions",
                "changed": changed, "source_seq": negatives[-1]["seq"]}

    def context(self, frontier=(), budget=2000, conditions=None):
        store = self.fold()
        try:
            sliced = Assembler(store).build_slice(frontier, budget=budget)
        finally:
            store.close()
        # Suppression is computed from the full journal, never the token-budgeted slice.
        negatives = [r["payload"] for r in self.journal.events() if r["kind"] == "verification"
                     and r["payload"].get("verdict") == "negative"]
        checks = {p["action_key"]: self.retry(p["action_key"], conditions or {}) for p in negatives}
        text = ("CAIRN: remembered evidence is not a fresh proof. Negative results apply ONLY to their recorded conditions.\n"
                + sliced.text + "\nRetry guards: " + canonical(checks))
        served = {"text": text, "stats": sliced.stats, "conditions": conditions or {},
                  "context_hash": digest(text)}
        self.journal.append("context", served)
        return served

    def panel(self):
        store = self.fold()
        try:
            items = [asdict(i) for i in store.live()]
        finally:
            store.close()
        events = self.journal.events()
        for item in items:
            try:
                value = json.loads(item["content"])
                item["summary"] = f"{value.get('verdict', item['status'])}: {value.get('reason', value.get('claim', item['content']))}"
            except (ValueError, TypeError):
                item["summary"] = item["content"]
        contexts = [r["payload"] for r in events if r["kind"] == "context"]
        current = contexts[-1] if contexts else {"text": "No manager context served yet", "conditions": {}}
        negatives = [r for r in events if r["kind"] == "verification" and r["payload"].get("verdict") == "negative"]
        changed = [{"action_key": r["payload"]["action_key"], **self.retry(r["payload"]["action_key"], current["conditions"])} for r in negatives]
        completed = {r["payload"].get("intent_seq") for r in events if r["kind"] == "observation"}
        uncertain = [r["seq"] for r in events if r["kind"] == "intent" and r["seq"] not in completed]
        return {"battle": self.entity, "known": [i for i in items if i["status"] == "verified" and i["layer"] != "negative"],
                "suspected": [i for i in items if i["status"] == "hypothesis"],
                "already_tried": [i for i in items if i["layer"] == "negative"],
                "changed": [c for c in changed if c["changed"]], "context": current,
                "next_check": "Re-check changed conditions; otherwise test an unverified hypothesis with owner / other / anonymous controls.",
                "tutor": {"why": "Compare the same private resource using independently identified principals.",
                          "supports": "Other principal reads the owner's resource while anonymous is denied.",
                          "disproves": "Owner succeeds, but both other and anonymous are denied.",
                          "inconclusive": "Timeout, wrong identity, redirect, missing controls, changed generation, or an unusable owner response."},
                "unresolved_intents": uncertain,
                "receipt_count": len(events), "chain_head": events[-1]["hash"] if events else None}
