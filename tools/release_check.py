#!/usr/bin/env python3
"""Bounded release canary: Opus selects two controlled checks (ten HTTP requests).

Uses only a disposable loopback fixture, and labels policy approvals honestly.
Optional browser test checks the actual rendered panel and a source link.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from runtime_fixture import runtime_fixture
from bs2.benchmark import restart_benchmark
from bs2.memory import BattleMemory
from bs2.panel import server

ROOT = Path(__file__).resolve().parents[1]


def opus(prompt):
    proc = subprocess.run(["claude", "-p", "--model", "opus", "--effort", "medium", "--tools", "",
                           "--strict-mcp-config", "--setting-sources", "", "--settings", '{"disableAllHooks":true}',
                           "--no-session-persistence", "--output-format", "json"],
                          input=prompt, capture_output=True, text=True, timeout=120, cwd=ROOT)
    if proc.returncode:
        raise RuntimeError("Opus call failed: " + proc.stderr[:200])
    envelope = json.loads(proc.stdout)
    raw = envelope["result"].strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.splitlines()[1:-1])
    return json.loads(raw), {"session_id": envelope.get("session_id"), "usage": envelope.get("usage"),
                             "model_usage": envelope.get("modelUsage"), "num_turns": envelope.get("num_turns")}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--opus", action="store_true")
    p.add_argument("--browser", action="store_true")
    p.add_argument("--out", required=True)
    args = p.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    report = {"scope": "disposable loopback fixture only", "max_http_requests": 10, "driver": "opus" if args.opus else "deterministic", "turns": []}
    with tempfile.TemporaryDirectory(prefix="bs2-release-") as temp:
        with runtime_fixture(Path(temp) / "fixture") as f:
            doctor = subprocess.run([sys.executable, "scripts/bs2-doctor", "--require-hitl", "--json"],
                                    capture_output=True, text=True, cwd=ROOT, timeout=25)
            health = json.loads(doctor.stdout)
            report["doctor"] = {"result": health["result"], "checks": health["checks"]}
            if health["result"] == "fail":
                raise RuntimeError(health["report_text"])
            remaining = ["check_private", "check_guarded"]
            memory = BattleMemory(f["directory"])
            for turn in range(2):
                context = memory.context(["private-resource verification"])
                prompt = ("You are Opus driving a bounded BS2 release test. No tools, specialists or open-ended work. "
                          "Choose one offered controlled read check. Each check validates two identities then compares owner/other/anonymous (5 requests). "
                          "The operator authorizes only the disposable local fixture. Do not invent a verdict. Return only JSON {\"action\":\"offered_name\",\"why\":\"short reason\"}. "
                          f"Offered: {remaining}. Prior results: {json.dumps(report['turns'])}. Cairn context:\n{context['text']}")
                choice, meta = opus(prompt) if args.opus else ({"action": remaining[0], "why": "deterministic smoke"}, {})
                if choice.get("action") not in remaining:
                    raise RuntimeError("driver chose an unoffered or repeated action")
                action = choice["action"]; remaining.remove(action)
                route = "/private/1" if action == "check_private" else "/guarded/1"
                env = dict(os.environ, BS2_OWNER_TOKEN=f["kwargs"]["owner"][1], BS2_OTHER_TOKEN=f["kwargs"]["other"][1])
                command = [sys.executable, "-m", "bs2.cli", "--run-dir", f["directory"], "check-read",
                           "--base", f["base"], "--route", route, "--identity-route", "/whoami", "--owner", "alice", "--other", "bob",
                           "--resource-id", "1", "--private-contract", f["kwargs"]["private_contract"],
                           "--generation", "fixture-v1", "--session-epoch", "fixture-session-1"]
                child = subprocess.run(command, capture_output=True, text=True, env=env, cwd=ROOT, timeout=35, check=True)
                result = json.loads(child.stdout)
                expected = "confirmed" if action == "check_private" else "negative"
                if result["verdict"] != expected:
                    raise RuntimeError(f"fixture result mismatch: {result}")
                report["turns"].append({"choice": choice, "result": result, "opus": meta, "served_context_hash": context["context_hash"]})
                print(f"Turn {turn+1}: {action} -> {result['verdict']}", flush=True)
            report["http_requests"] = len(f["contacts"])
            assert report["http_requests"] == 10
            assert len(f["decisions"]) == 10
            report["approvals"] = {"count": 10, "actor": "fixture-policy", "not_human_clicks": True}
            context = memory.context(["private-resource verification"])
            if args.browser:
                from playwright.sync_api import sync_playwright
                srv = server(f["directory"], 0)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                try:
                    with sync_playwright() as pw:
                        browser = pw.chromium.launch(headless=True)
                        page = browser.new_page(viewport={"width": 1440, "height": 1100})
                        errors = []; page.on("pageerror", lambda e: errors.append(str(e)))
                        page.goto(f"http://127.0.0.1:{srv.server_port}")
                        page.locator("#known .item").first.wait_for()
                        assert page.locator("#context").inner_text() == context["text"]
                        assert page.locator("#already_tried .item").count() > 0
                        assert not errors
                        page.screenshot(path=str(out / "operator-panel.png"), full_page=True)
                        page.locator("#known a").first.click()
                        assert '"kind": "observation"' in page.locator("body").inner_text()
                        browser.close()
                    report["browser"] = {"rendered": True, "exact_context": True, "source_link": True, "console_errors": errors}
                finally:
                    srv.shutdown(); srv.server_close()
            report["benchmark"] = restart_benchmark(Path(temp) / "restart")
            if args.opus:
                judgment, meta = opus("You are Opus judging your bounded BS2 release canary. Return JSON {\"pass\":true|false,\"reason\":\"short\",\"limits\":[...]}. "
                                      "Judge only measured results. Require 10 fixture requests, one confirmed check, one controlled negative, exact approvals and restart memory. "
                                      "Containment supports pinned HTTP only, not OS-isolated arbitrary tools. Synthetic benchmark is NOT a real engagement performance claim.\n" + json.dumps(report))
                report["opus_judgment"] = {"judgment": judgment, "usage": meta}
                assert judgment.get("pass") is True, judgment
    (out / "validation.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"ok": True, "report": str(out / "validation.json"), "http_requests": report["http_requests"]}))


if __name__ == "__main__":
    main()
