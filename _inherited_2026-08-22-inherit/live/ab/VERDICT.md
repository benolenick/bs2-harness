# gunbelt AUTOCANNON — A/B verdict (2026-08-21)

Two autocannons, both twins, fresh reset each run, **every DC-owned claim independently
re-verified with guest-proof rpcclient auth** (so a false positive can't score as a win).

| engine | box  | wall  | shots | flags(values) | DC owned | DC auth REAL | cred source |
|--------|------|-------|-------|---------------|----------|--------------|-------------|
| mine (carousel)     | lab  |  4.76s | 26 | **3/3** | yes | **yes** | derived (GPU1 phpass crack) |
| theirs (autocannon) | lab  | 83.15s | 41 | 1       | yes | yes     | hardcoded (answer-key) |
| mine (carousel)     | lab2 |  4.55s | 26 | **3/3** | yes | **yes** | derived (GPU1 phpass crack) |
| theirs (autocannon) | lab2 | 60.2s  | 41 | 1       | yes | yes     | hardcoded (answer-key) |

## Where each wins
**Mine wins:** speed (13–18×), flag-VALUE capture (3/3 vs 1 — theirs lists the ftp dir but
never GETs the file, and its webroot flag-hunt misses /var/www/html), credential DERIVATION
(cracks the phpass hash → tom:charlie1 blind, vs baking the answer key into the belt),
verification honesty (rpcclient getusername, guest-proof — vs smbclient -L, which the samba
box answers for *guest*, so it would green-light a wrong cred), and pivot realism (real chisel
reverse-SOCKS through the web RCE — works on a genuinely segmented target; theirs fires DC
shots straight from the your-host host, relying on host routing, and by its own mailbox is "not
usable against a live HTB box as-is").

**Theirs wins:** RECON generality (real `nmap -sn`/`-sV` discovery, no hardcoded IPs — ~24s of
its wall-clock, and the reason it's slower; mine hardcodes the layout), broader web coverage
(22 probe paths + ffuf → 41 shots vs 26), and operator legibility (the live war-room viz).

## Reconciliation (the merge, not a winner)
theirs' **nmap-discovery front-end + catalog-driven belt + war-room viz**  →  feeding
mine's **event-driven honest-verify execution core** (GPU crack, real pivot, rpcclient auth,
file-content flag capture). Discovery generality + fast honest execution = one engine.

Artifacts: carousel.py (mine), warroom_headless.py (faithful headless port of theirs),
ab.py (harness), report.json (raw). Their source: warroom.py @ tag autocannon-claude-v1.
