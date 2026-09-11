#!/usr/bin/env python3
"""gunbelt LIVE engine — the programmatic parallel Carousel. NO LLM in the hot loop.

  frontier (Ariadne, ~100ms)  ->  gunbelt.select() picks lanes  ->  fire the whole breadth
  CONCURRENTLY as subprocesses  ->  fuzzy gate (baseline-delta + nonce-on-listener; 1.7b ONLY
  on Amber)  ->  apply confirmed facts / prune negatives  ->  re-plan  ->  repeat.

Speed = no agent between actions. Opus "cortex" wakes only when the 1.7b says `wake` or the
frontier stalls. Content-blind: lanes emit signals/metadata, never raw payloads to the operator.
"""
import asyncio, argparse, json, os, sys, time, re, secrets, shlex
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "catalog"))
import loader

# ---- param provider: fills recipe invocation templates with concrete values ----
def make_params(target, lhost, lport_base, recon):
    return {
        "host": target, "ip": target,
        "port": None,                         # set per-lane from recon ports
        "domain": recon.get("domain", "inlanefreight.local"),
        "url": f"http://{target}/",
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "LHOST": lhost, "LPORT": None,        # set per-lane (unique listener port)
        "dc": recon.get("dc", ""), "userlist": "users.txt", "passlist": "pass.txt",
        "hashfile": "hashes.txt", "table": "users",
        "edb_id": recon.get("edb_id", ""), "exploit": recon.get("exploit", ""),
        "user": recon.get("user", "admin"), "pass": recon.get("pass", ""),
        "webroot": "/var/www/html", "lfi_param": "0",
    }

def render(recipe, params, nonce):
    inv = recipe.get("invocation", "").strip()
    p = dict(params); p["NONCE"] = nonce
    def sub(m):
        k = m.group(1)
        v = p.get(k, "")
        return str(v) if v is not None else ""
    return re.sub(r"\{\{(\w+)\}\}", sub, inv)

# ---- lane execution: one recipe -> one concurrent subprocess (or probe fan) ----
async def fire_lane(recipe, params, sem, rate_delay, timeout, dry):
    nonce = "gb" + secrets.token_hex(4)
    cmd = render(recipe, params, nonce)
    lane = {"id": recipe["id"], "cmd": cmd, "nonce": nonce,
            "callback": recipe.get("callback", "none"),
            "confirms": recipe.get("confirms", []), "t": 0.0}
    if dry:
        lane["result"] = "(dry-run: not fired)"; return lane
    async with sem:
        await asyncio.sleep(rate_delay)
        t0 = time.time()
        try:
            try:
                from . import target_exec
            except ImportError:
                import target_exec
            out = await asyncio.to_thread(target_exec.run, cmd, params.get("host"), timeout=timeout)
            lane["result"] = out[:4000]
            lane["rc"] = -1 if out.startswith("[target-exec") else 0
        except asyncio.TimeoutError:
            lane["result"] = "(timeout)"; lane["rc"] = -1
        except Exception as e:
            lane["result"] = f"(error: {e})"; lane["rc"] = -2
        lane["t"] = round(time.time() - t0, 2)
    return lane

async def volley(recipes, params, max_parallel, rate, timeout, dry):
    sem = asyncio.Semaphore(max_parallel)
    tasks = [fire_lane(r, params, sem, i * (1.0 / max(rate, 1)), timeout, dry)
             for i, r in enumerate(recipes)]
    return await asyncio.gather(*tasks)

# ---- demo entry: show the PARALLEL PLAN for a target's current ctx ----
def plan_only(target):
    ctx = loader.facts_from_map  # not used; build a minimal starting ctx
    start = {"services": {"ftp","dns","http","smb"}, "ports": {21,53,80,445},
             "products": set(), "flags": {"is_dc": False, "dc_ip": None},
             "have": set(), "hosts": []}
    lanes = loader.select(start, dial="full", parallel_safe=True)
    return start, lanes

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--lhost", default="10.10.14.153")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max-parallel", type=int, default=16)
    ap.add_argument("--rate", type=float, default=10)
    ap.add_argument("--timeout", type=float, default=30)
    a = ap.parse_args()
    ctx, lanes = plan_only(a.target)
    params = make_params(a.target, a.lhost, 4444, {})
    print(f"# gunbelt live engine — target {a.target}")
    print(f"# opening PARALLEL VOLLEY: {len(lanes)} concurrent lanes (max_parallel={a.max_parallel})")
    res = asyncio.run(volley(lanes, params, a.max_parallel, a.rate, a.timeout, a.dry_run))
    for r in res:
        print(f"  [{r['id']:18}] cb={r['callback']:13} nonce={r['nonce']}  $ {r['cmd'][:90]}")
    if not a.dry_run:
        fired = [r for r in res if r.get('t')]
        print(f"# fired {len(fired)} lanes concurrently; slowest {max((r['t'] for r in fired), default=0)}s "
              f"(serial would be ~{round(sum(r['t'] for r in fired),1)}s)")
