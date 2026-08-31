# cartographer — the keeper of the box's live map

**Why it exists.** `HOW_I_BROKE_BATTLESTATION_AND_HOW_IT_SHOULD_WORK.md` is the postmortem:
the manager kept holding "what's on the box AND what I haven't looked at yet" only in its
context window, which drifts and evaporates, so it re-enumerated nothing and froze its live
thinking into hardcoded `if <vuln-shape>:` branches. Ariadne does NOT fix this — Ariadne
plans exploit *chains*; it has no notion of a *discovery* frontier. That job had no owner.
This is the owner.

**What it is.** One durable artifact `<run-dir>/cartography.json` + a deterministic module.
Every surface item (host / port / app / endpoint / vhost / cred / share …) is a node with a
lifecycle state:

    untouched  → enumerating → exhausted        (all discovery rituals run)
                              → led-to-foothold  (produced code-exec or a cred)
                              → dead             (confirmed dead end)

The **discovery frontier** = untouched/enumerating nodes, ranked by operator payoff. Each
row carries the enumeration *classes* a real pentester always checks (dirs, vhosts, shares,
cve-lookup, spray…) — the manager reads those and AUTHORS the actual probe. We never encode
"this box has bug X"; only "an http port always gets its vhosts enumerated."

**The contract (matches the postmortem's "how it SHOULD work"):**
- Writer is CODE, never the LLM — `fold()` is deterministic; the manager can't drift the map.
- Manager READS `frontier()`, PICKS the top untouched edge, AUTHORS the probe. No frozen branches.
- Ariadne is a CONSULTANT — `ariadne_triple()` feeds recon_advisor.advise_from_state();
  the cartographer feeds Ariadne rather than competing with it.
- Content-blind — node labels are non-secret handles; cred secrets are never written (user + flag only).

## CLI
    cartographer.py init     --run-dir DIR [--target IP]   # seed nodes from an existing map.json
    cartographer.py fold     --run-dir DIR  < obs          # fold observations; update lifecycle
    cartographer.py frontier --run-dir DIR [--top N --json]# ranked untouched edges (the manager's pick-list)
    cartographer.py show     --run-dir DIR                 # the map as a state tree
    cartographer.py ariadne  --run-dir DIR                 # (apps,proven,extra_facts) for recon_advisor

Set `PYTHONPATH` to include `gunbelt/manager` (for htb_observations) and `gunbelt/live`.
Caller stamps time via env `CARTO_TS` (scripts have no Date.now); pass real epoch seconds.

## Observation grammar (fold reads stdin, one per line, or a JSON array)
Discovery (htb_observations shape):  `web8080=... osTicket /scp/`, `sqli=...`, `cred=user:pass`, `vhost: dev.box`
Lifecycle control:
    enum=<hint>:<ritual>   one ritual of a matched node done   (all done → exhausted)
    done=<hint>            mark a node exhausted
    dead=<hint>            confirmed dead end
    foothold=<hint> | shell=… | rce=…   node (and host) → led-to-foothold

## The manager loop it enables
    read frontier() → pick top untouched edge → author probe → run → append observation →
    fold() → repeat.  Call Ariadne (via ariadne_triple → recon_advisor) once the map is rich
    enough to plan a chain.

## FRONTEND — TODO (Ben, 2026-08-24)
BS2's **Terrain** tab ("No typed terrain has been projected yet") is the visual projection
of this ledger. The cartographer is the data source that fills the terrain: nodes → terrain
features, states → fog/spotted/reachable/owned coloring, frontier → the "NEEDS YOU"
highlights. Wire cartography.json → the Terrain panel when we build the frontend.

---

# hands — the recon executor (THE MISSING LINK)

`live/hands.py`. The cartographer records; it never touches the target. **hands** is the piece
that was missing: it reads a frontier edge, runs the RIGHT your-host tool with the RIGHT wordlist,
scrubs the output to observations, and folds them back — so the map MAKES ITSELF.

    frontier() → hands.run() → [your-host arsenal over ssh] → observations → fold() → map grows → repeat

- Runs on **your-host** (fleet .129): nmap/gobuster/ffuf/whatweb/netexec/nuclei/searchsploit +
  seclists + wordlists + RAG corpus. Every target-touching command runs there, over ssh
  (`bash -lc` login shell), with a timeout; ANSI stripped before parsing.
- **Discovery only.** Enumeration rituals (dirs/vhosts/tech-fingerprint/anon-login/shares/
  version-cve/axfr) are standard tradecraft — safe to encode. Exploitation rituals
  (default-creds/injection/authz-diff/cred-spray/exploit-chain) are in DEFERRED: logged,
  never fired — the manager owns those (the postmortem's rule).
- Structural findings (web paths, vhosts, shares, creds) fold into global nodes; free-form
  findings (cve-candidate titles) attach as NOTES on the probed node so nothing evaporates.

CLI:
    hands.py run  --run-dir DIR [--target IP] [--top N] [--dry-run] [--host your-host]
    hands.py loop --run-dir DIR [--rounds K] [--dry-run]        # drive until frontier dry

`--dry-run` prints the exact your-host commands without firing — safe to inspect before pointing
at a live, authorized target. Caller stamps time via env HANDS_TS (scripts have no Date.now).

OPEN: full-port-sweep is marked done on ingest (map.json already IS a sweep); a live nmap
action that folds NEW ports as nodes is the next hands upgrade. RAG-tuned wordlist/nuclei
selection per product (your-host corpus) is the enhancement after that.
