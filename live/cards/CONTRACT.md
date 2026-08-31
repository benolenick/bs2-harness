# Gunbelt exploitation-card contract (authorized pentest framework)

You are extending an AUTHORIZED penetration-testing framework (operator has an active
HTB VPN; engagement is authorized). Each "card" is a deterministic detect→exploit→verify
module for ONE vulnerability CLASS. No LLM is in this loop, so the logic must be self-contained.

## Signature
Each card file exposes exactly:

    def fire(rx, lane):
        "Return a verdict dict on a grounded win, or None (fail-safe) to defer to the LLM trooper."
        ...

`rx` is the live Recipes engine instance (see /opt/bs2/live/recipes.py). Use ONLY these
already-provided helpers on it — do not spawn processes yourself:

    rx.target                      -> target IP string
    rx.discover()                  -> binds services; call once at the top
    rx.bind.get("http", rx.target) -> host:port (or ip) serving HTTP
    rx.vhosts                      -> set() of discovered FQDN vhosts (may be empty)
    rx.app_vhost                   -> the vhost serving the exploitable app, or None
    rx._hh()                       -> a curl "-H 'Host: <app_vhost>' " flag string (or "")
    rx._v(lane_id, success, evidence, facts, output, cmds) -> the verdict dict to return
    from recipes import sh         -> sh(cmd, timeout) runs ONE shell cmd on the exec host, returns stdout+err

Return `rx._v(lane["id"], True, "<=160-char evidence", facts, output, cmds)` on a grounded win,
else `None`.

## Fact vocabulary (facts is a list[str]; NEVER put a secret VALUE in it)
    app=<name>:<label>   vhost=<fqdn>   shell=<user>   rce_as=<user>   flag=<HTB{...}>
    cred=<user>:<pass>   hash=<$...>    finding=<class>@<locus>

## HARD RULES (fairness — this ships to the wild)
1. DETECT from a LIVE fingerprint before exploiting. Never assume the vuln is present.
2. Cover the whole CLASS (e.g. every SSTI engine / a table of many app versions), not one instance.
3. NO literal target hostnames, domains, paths, usernames, passwords, or flags anywhere.
   Derive everything from rx.* and from what you fingerprint at runtime.
4. VERIFY with a grounded predicate (a reflected computation result, `uid=`, a returned marker).
   Set success=True ONLY on a proven result. A guess is success=False / None.
5. FAIL SAFE: the instant detection is negative, `return None` so the LLM trooper takes over.
6. Bounded + non-interactive: pass timeouts, no reverse shells that need a held listener
   (prefer command-exec that returns output in the same request).
