#!/usr/bin/env python3
"""Additional test only: real Trooper.fire + Opus driver and command author.

Eight model calls max (driver, six trooper turns, resumed driver); seven fixture
HTTP requests max. Uses the production tool-disabled Claude CLI launcher.
Additional test allowlist contains model mistakes before dispatch. No live
campaign data or target outside the disposable fixture is accessed.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from runtime_fixture import runtime_fixture
from bs2.journal import digest
from bs2.memory import BattleMemory
from bs2.session import environment, check_private_read
from bs2.verification import verify_read
from bs2.transport import prepare
from live import trooper


def parse_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(text.splitlines()[1:-1])
    return json.loads(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "scope": "disposable loopback fixture; no live targets", "model_call_cap": 8,
              "fixture_request_cap": 7, "model_calls": [], "requests": [], "rejections": [],
              "overrides": ["test-only exact route/principal allowlist; production model launcher, run_cmd and target_exec"],
              "stock_launcher_tested_live": True}

    def save():
        (out / "report.json").write_text(json.dumps(report, indent=2))

    def ask_opus(role, prompt):
        if len(report["model_calls"]) >= 8:
            raise RuntimeError("model call cap reached")
        entry = {"role": role, "prompt_digest": digest(prompt), "started": time.time()}
        report["model_calls"].append(entry); save()
        print(f"Opus {role}: call {len(report['model_calls'])}/8", flush=True)
        proc = subprocess.run(["claude", "-p", "--model", "opus", "--effort", "medium", "--tools", "",
                               "--strict-mcp-config", "--setting-sources", "", "--settings", '{"disableAllHooks":true}',
                               "--no-session-persistence", "--output-format", "json"],
                              input=prompt, capture_output=True, text=True, timeout=100, cwd=ROOT)
        entry["elapsed_seconds"] = round(time.time() - entry["started"], 3)
        if proc.returncode:
            entry["error"] = proc.stderr[:300]; save()
            raise RuntimeError("Opus adapter failed")
        envelope = json.loads(proc.stdout)
        result = envelope.get("result", "")
        entry.update(response=result, session_id=envelope.get("session_id"), usage=envelope.get("usage"),
                     model_usage=envelope.get("modelUsage"), num_turns=envelope.get("num_turns"))
        save()
        if envelope.get("is_error") or envelope.get("num_turns", 1) != 1:
            raise RuntimeError("Opus did not complete a single tool-free turn")
        return result

    try:
        with runtime_fixture(out / "fixture") as f, environment(TROOPER_BASE="claude-cli", TROOPER_MODEL="opus", TROOPER_KEY_FILE=""):
            doctor = subprocess.run([sys.executable, "scripts/bs2-doctor", "--require-hitl", "--json"], cwd=ROOT,
                                    capture_output=True, text=True, timeout=25)
            health = json.loads(doctor.stdout)
            report["doctor"] = health
            if health["result"] == "fail":
                raise RuntimeError(health["report_text"])
            print("Doctor:", health["result"], "(fixture broker and policy configured)", flush=True)
            memory = BattleMemory(f["directory"])
            route = "/guarded/1"
            driver_prompt = (
                "You are Opus, DRIVER of a bounded BS2 test. Delegate ONE controlled private-resource read check to a separate Opus TROOPER. "
                "You cannot execute tools and must not invent observations. The only target is a disposable authorized loopback fixture. "
                f"Base: {f['base']}; resource route: {route}; resource id: 1; identity route /whoami returns principal_id. "
                "Resource policy: private to owner alice. Test principals: alice (owner) and bob (other), plus anonymous. "
                "Design the objective so the trooper obtains both identity controls and all three resource responses in five separate requests, "
                "then stops. Do not supply the exact curl strings: the trooper must author them. "
                "Output ONLY JSON {\"objective\":\"...\",\"why\":\"...\",\"evidence_needed\":[...]}. "
                "No expected result is given; successful access-control enforcement is as informative as a vulnerability. "
                "A later resumed driver will decide whether the same check needs repeating. Cairn:\n" + memory.context()["text"])
            plan = parse_json(ask_opus("driver", driver_prompt))
            report["driver_plan"] = plan
            if not isinstance(plan.get("objective"), str):
                raise ValueError("driver objective missing")
            allowed = {(route, "alice"), (route, "bob"), (route, "anonymous"), ("/whoami", "alice"), ("/whoami", "bob")}
            completed = {}
            original_chat, original_run, original_turns = trooper._chat, trooper.run_cmd, trooper.MAX_TURNS

            def observed_chat(messages, key):
                if len(report["model_calls"]) >= 8:
                    raise RuntimeError("model call cap reached")
                entry = {"role": "trooper", "prompt_digest": digest(messages), "started": time.time(),
                         "launcher": "live.trooper._chat_claude (production)", "configured_model": os.environ["TROOPER_MODEL"]}
                report["model_calls"].append(entry); save()
                print(f"Opus trooper (production): call {len(report['model_calls'])}/8", flush=True)
                result = original_chat(messages, key)
                entry.update(response=result, elapsed_seconds=round(time.time() - entry["started"], 3))
                save()
                return result

            def gated_request(command, target):
                before = len(memory.journal.events())
                try:
                    if len(f["contacts"]) >= 5:
                        raise ValueError("five-request comparison cap reached")
                    prepared = prepare(command, f["base"], json.loads(f["policy"].read_text()), 10)
                    if prepared["method"] != "GET" or prepared["body"] is not None:
                        raise ValueError("comparison allows GET with no body only")
                    headers = prepared["headers"]
                    if set(headers) - {"authorization"}:
                        raise ValueError("unexpected header in test request")
                    credential = headers.get("authorization", "")
                    principal = {"Bearer fixture-owner-token": "alice", "Bearer fixture-other-token": "bob", "": "anonymous"}.get(credential)
                    slot = (prepared["path"], principal)
                    if slot not in allowed or slot in completed:
                        raise ValueError("unoffered or repeated route/principal pair")
                except Exception as exc:
                    report["rejections"].append({"command_digest": digest(command), "reason": str(exc)})
                    save()
                    return f"[target-exec BLOCKED: bounded fixture scope: {exc}]"
                with environment(BS2_PRINCIPAL_ID=principal):
                    output = original_run(command, target)
                fresh = [r for r in memory.journal.events()[before:] if r["kind"] == "observation"]
                if fresh:
                    row = fresh[-1]; completed[slot] = row["seq"]
                    report["requests"].append({"route": slot[0], "principal": principal, "status": row["payload"]["status"],
                                               "command_digest": digest(command), "receipt_seq": row["seq"], "receipt_hash": row["hash"]})
                save()
                print("Trooper request:", slot, "->", fresh[-1]["payload"]["status"] if fresh else "refused/inconclusive", flush=True)
                return output

            objective = (plan["objective"] + f"\nTest scope: exactly five unique GET requests among {sorted(allowed)} at {f['base']}. "
                         "Use plain curl -sS -i with the exact absolute URL; no -k, -L, pipelines, local file reads, other tools or other hosts. "
                         "alice credential header: Authorization: Bearer fixture-owner-token. "
                         "bob credential header: Authorization: Bearer fixture-other-token. Anonymous must send no Authorization header. "
                         "You have SIX turns total: five one-command turns, then VERDICT with factual telemetry. "
                         "Do not claim a vulnerability or shell from text markers. A denied other-principal read is a valid negative observation.")
            try:
                trooper._chat, trooper.run_cmd, trooper.MAX_TURNS = observed_chat, gated_request, 6
                result = trooper.Trooper(key="fixture-only").fire({"id": "dual-opus-local", "target": f["base"], "objective": objective})
            finally:
                trooper._chat, trooper.run_cmd, trooper.MAX_TURNS = original_chat, original_run, original_turns
            report["trooper_result"] = result
            if set(completed) != allowed:
                raise RuntimeError("Trooper did not obtain all five unique controls within budget")
            proof = verify_read(f["directory"], owner=completed[(route, "alice")], other=completed[(route, "bob")],
                                anonymous=completed[(route, "anonymous")], owner_identity=completed[("/whoami", "alice")],
                                other_identity=completed[("/whoami", "bob")], resource_id="1",
                                private_contract=f["kwargs"]["private_contract"])
            report["controlled_verification"] = proof
            if proof["verdict"] != "negative":
                raise RuntimeError("Controlled verifier did not match fixture oracle")
            # New interpreter restores the actual per-battle memory, not a summary
            # of the earlier chat. No previous model session is resumed or reused.
            code = ("import json,sys; from bs2.memory import BattleMemory; m=BattleMemory(sys.argv[1]); "
                    "p=json.loads(sys.argv[2]); print(json.dumps({'context':m.context(conditions=p['conditions']), "
                    "'same':m.retry(p['action_key'],p['conditions']), 'changed':m.retry(p['action_key'], "
                    "dict(p['conditions'],target_generation='fixture-v2'))}))")
            child = subprocess.run([sys.executable, "-c", code, f["directory"], json.dumps(proof)], cwd=ROOT,
                                   capture_output=True, text=True, timeout=20, check=True)
            restored = json.loads(child.stdout)
            report["restart"] = {"fresh_interpreter": True, "same": restored["same"], "changed": restored["changed"],
                                 "context_hash": restored["context"]["context_hash"]}
            resumed = parse_json(ask_opus("resumed-driver", "You are a fresh Opus DRIVER after restart; prior chat is not supplied. "
                                         "Use Cairn and the actual retry guard results below. Return only JSON "
                                         "{\"same_conditions\":\"skip|recheck\",\"changed_generation\":\"skip|recheck\",\"why\":\"short\"}. "
                                         "Do not invent fresh evidence; a prior negative is condition-bound.\n" + json.dumps(restored)))
            report["resumed_driver"] = resumed
            assert resumed["same_conditions"] == "skip" and resumed["changed_generation"] == "recheck"
            before = len(f["contacts"])
            report["repeat_check"] = check_private_read(f["directory"], base=f["base"], route=route, **f["kwargs"])
            assert report["repeat_check"]["verdict"] == "suppressed" and len(f["contacts"]) == before
            # Two additional read-only diagnostics, not an open-ended trooper lane.
            diagnostics = []
            for path, expected in (("/redirect", 302), ("/forged", 403)):
                output = original_run(shlex.join(["curl", "-sS", "-i", f["base"] + path]), f["base"])
                receipt = trooper._texec._GOVERNANCE_CONTEXT.last_receipt
                assert receipt and receipt["payload"]["status"] == expected
                diagnostics.append({"path": path, "status": expected, "receipt_seq": receipt["seq"]})
            report["diagnostics"] = diagnostics
            before = len(f["contacts"])
            denial = original_run("curl -L " + f["base"] + "/redirect", f["base"])
            assert "BLOCKED" in denial and len(f["contacts"]) == before
            report["redirect_follow_refused"] = True
            report["http_requests"] = len(f["contacts"])
            report["approval_count"] = len(f["decisions"])
            report["approval_actor"] = "fixture-policy (not human clicks)"
            report["panel_projection"] = {"negative_items": len(memory.panel()["already_tried"]),
                                           "unresolved_intents": memory.panel()["unresolved_intents"]}
            assert report["http_requests"] <= 7 and report["approval_count"] == report["http_requests"]
            report["bounded_fixture_pass"] = True
    except BaseException as exc:
        report["bounded_fixture_pass"] = False
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        save()
        print(json.dumps({"pass": report.get("bounded_fixture_pass"), "calls": len(report["model_calls"]),
                          "requests": report.get("http_requests"), "report": str(out / "report.json")}), flush=True)


if __name__ == "__main__":
    main()
